package ai.pipestream.opensearch.acl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.explain.ExplainAction;
import org.opensearch.action.explain.ExplainRequest;
import org.opensearch.action.explain.ExplainResponse;
import org.opensearch.action.get.GetAction;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
import org.opensearch.action.termvectors.TermVectorsAction;
import org.opensearch.action.termvectors.TermVectorsRequest;
import org.opensearch.action.termvectors.TermVectorsResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.tasks.Task;
import org.opensearch.transport.client.Client;

/**
 * Hides documents of ACL protected indices from get, multi get, explain and term vectors when the caller's
 * principals do not pass the document's ACL. A hidden document is answered as not found.
 */
public final class AclDocumentReadFilter implements ActionFilter {

    /** Thread context transient that marks the filter's own ACL lookups. */
    static final String LOOKUP_TRANSIENT = "_protomolt_acl_lookup";

    private final Supplier<ClusterState> clusterState;
    private final Supplier<ThreadContext> threadContext;
    private final Supplier<Client> client;
    private final AclFields fields;

    /**
     * Creates the filter.
     *
     * @param clusterState supplies the current cluster state
     * @param threadContext supplies the node's thread context
     * @param client supplies the node client used to read ACL fields
     * @param fields the ACL field names
     */
    public AclDocumentReadFilter(
            Supplier<ClusterState> clusterState,
            Supplier<ThreadContext> threadContext,
            Supplier<Client> client,
            AclFields fields) {
        this.clusterState = clusterState;
        this.threadContext = threadContext;
        this.client = client;
        this.fields = fields;
    }

    @Override
    public int order() {
        return AclSearchFilter.ORDER;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
            Task task,
            String action,
            Request request,
            ActionRequestMetadata<Request, Response> actionRequestMetadata,
            ActionListener<Response> listener,
            ActionFilterChain<Request, Response> chain) {
        boolean documentRead = GetAction.NAME.equals(action)
                || MultiGetAction.NAME.equals(action)
                || ExplainAction.NAME.equals(action)
                || TermVectorsAction.NAME.equals(action)
                || MultiTermVectorsAction.NAME.equals(action);
        if (!documentRead
                || threadContext.get().getTransient(LOOKUP_TRANSIENT) != null
                || !mayTouchProtected(actionRequestMetadata.resolvedIndices())) {
            chain.proceed(task, action, request, listener);
            return;
        }
        if (MultiTermVectorsAction.NAME.equals(action)) {
            listener.onFailure(badRequest("multi term vectors is not supported on ACL protected indices"));
            return;
        }
        if (request instanceof TermVectorsRequest termVectors && (termVectors.doc() != null || termVectors.termStatistics())) {
            listener.onFailure(badRequest("artificial documents and term statistics are not supported on ACL protected indices"));
            return;
        }
        chain.proceed(task, action, request, new ActionListener<Response>() {
            @Override
            public void onResponse(Response response) {
                checkResponse(request, response, listener);
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    private <Response extends ActionResponse> void checkResponse(
            ActionRequest request, Response response, ActionListener<Response> listener) {
        List<Lookup> lookups = new ArrayList<>();
        if (response instanceof GetResponse get && request instanceof GetRequest getRequest) {
            addIfProtected(lookups, get.isExists(), get.getIndex(), get.getId(), getRequest.routing());
        } else if (response instanceof ExplainResponse explain && request instanceof ExplainRequest explainRequest) {
            addIfProtected(lookups, explain.isExists(), explain.getIndex(), explain.getId(), explainRequest.routing());
        } else if (response instanceof TermVectorsResponse tv && request instanceof TermVectorsRequest tvRequest) {
            addIfProtected(lookups, tv.isExists(), tv.getIndex(), tv.getId(), tvRequest.routing());
        } else if (response instanceof MultiGetResponse multiGet && request instanceof MultiGetRequest multiGetRequest) {
            MultiGetItemResponse[] items = multiGet.getResponses();
            for (int i = 0; i < items.length; i++) {
                GetResponse item = items[i].getResponse();
                if (item != null) {
                    addIfProtected(lookups, item.isExists(), item.getIndex(), item.getId(),
                            multiGetRequest.getItems().get(i).routing());
                }
            }
        }
        if (lookups.isEmpty()) {
            listener.onResponse(response);
            return;
        }
        Set<String> principals = CallerPrincipals.fromSecurityUserInfo(
                threadContext.get().getTransient(CallerPrincipals.SECURITY_USER_INFO_TRANSIENT));
        readAcls(lookups, ActionListener.wrap(
                acls -> listener.onResponse(redact(response, acls, principals)),
                listener::onFailure));
    }

    private void addIfProtected(List<Lookup> lookups, boolean exists, String index, String id, String routing) {
        if (exists && isProtected(index)) {
            lookups.add(new Lookup(index, id, routing));
        }
    }

    private void readAcls(List<Lookup> lookups, ActionListener<Map<Lookup, Map<String, Object>>> listener) {
        String[] includes = {fields.allow(), fields.deny(), fields.gates(), fields.complete()};
        MultiGetRequest lookupRequest = new MultiGetRequest().realtime(true);
        for (Lookup lookup : lookups) {
            lookupRequest.add(new MultiGetRequest.Item(lookup.index(), lookup.id())
                    .routing(lookup.routing())
                    .fetchSourceContext(new FetchSourceContext(true, includes, new String[0])));
        }
        ThreadContext context = threadContext.get();
        Supplier<ThreadContext.StoredContext> restore = context.newRestorableContext(false);
        ThreadContext.StoredContext stored = context.newStoredContext(false);
        try {
            context.putTransient(LOOKUP_TRANSIENT, Boolean.TRUE);
            client.get().multiGet(lookupRequest, new ContextPreservingActionListener<>(restore, ActionListener.wrap(
                    response -> {
                        Map<Lookup, Map<String, Object>> acls = new HashMap<>();
                        MultiGetItemResponse[] items = response.getResponses();
                        for (int i = 0; i < items.length; i++) {
                            GetResponse item = items[i].getResponse();
                            if (item != null && item.isExists()) {
                                acls.put(lookups.get(i), item.getSourceAsMap());
                            }
                        }
                        listener.onResponse(acls);
                    },
                    listener::onFailure)));
        } finally {
            stored.restore();
        }
    }

    private <Response extends ActionResponse> Response redact(
            Response response, Map<Lookup, Map<String, Object>> acls, Set<String> principals) {
        if (response instanceof GetResponse get) {
            return denied(acls, principals, get.getIndex(), get.getId()) ? cast(notFound(get.getIndex(), get.getId())) : response;
        }
        if (response instanceof ExplainResponse explain) {
            return denied(acls, principals, explain.getIndex(), explain.getId())
                    ? cast(new ExplainResponse(explain.getIndex(), explain.getId(), false))
                    : response;
        }
        if (response instanceof TermVectorsResponse tv) {
            if (denied(acls, principals, tv.getIndex(), tv.getId())) {
                TermVectorsResponse hidden = new TermVectorsResponse(tv.getIndex(), tv.getId());
                hidden.setExists(false);
                return cast(hidden);
            }
            return response;
        }
        if (response instanceof MultiGetResponse multiGet) {
            MultiGetItemResponse[] items = multiGet.getResponses();
            MultiGetItemResponse[] redacted = new MultiGetItemResponse[items.length];
            for (int i = 0; i < items.length; i++) {
                GetResponse item = items[i].getResponse();
                redacted[i] = item != null && item.isExists() && isProtected(item.getIndex())
                        && denied(acls, principals, item.getIndex(), item.getId())
                        ? new MultiGetItemResponse(notFound(item.getIndex(), item.getId()), null)
                        : items[i];
            }
            return cast(new MultiGetResponse(redacted));
        }
        return response;
    }

    private boolean denied(Map<Lookup, Map<String, Object>> acls, Set<String> principals, String index, String id) {
        for (Map.Entry<Lookup, Map<String, Object>> acl : acls.entrySet()) {
            if (acl.getKey().index().equals(index) && acl.getKey().id().equals(id)) {
                return !AclDocuments.allows(fields, acl.getValue(), principals);
            }
        }
        return true;
    }

    private boolean mayTouchProtected(OptionallyResolvedIndices resolved) {
        if (!(resolved instanceof ResolvedIndices known) || !known.remote().asRawExpressions().isEmpty()) {
            return true;
        }
        ClusterState state = clusterState.get();
        for (String name : known.local().namesOfIndices(state)) {
            if (isProtected(state, name)) {
                return true;
            }
        }
        return false;
    }

    private boolean isProtected(String index) {
        return isProtected(clusterState.get(), index);
    }

    private static boolean isProtected(ClusterState state, String index) {
        IndexMetadata metadata = state.metadata().index(index);
        return metadata != null && AclSettings.INDEX_ACL_ENABLED.get(metadata.getSettings());
    }

    private static GetResponse notFound(String index, String id) {
        return new GetResponse(new GetResult(index, id, SequenceNumbers.UNASSIGNED_SEQ_NO,
                SequenceNumbers.UNASSIGNED_PRIMARY_TERM, -1, false, null, null, null));
    }

    private static OpenSearchStatusException badRequest(String message) {
        return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST);
    }

    @SuppressWarnings("unchecked")
    private static <Response extends ActionResponse> Response cast(ActionResponse response) {
        return (Response) response;
    }

    /**
     * A document whose ACL fields are read.
     *
     * @param index concrete index name
     * @param id document id
     * @param routing routing value, or null
     */
    private record Lookup(String index, String id, String routing) {
    }
}
