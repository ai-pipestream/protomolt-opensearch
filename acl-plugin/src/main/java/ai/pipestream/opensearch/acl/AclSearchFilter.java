package ai.pipestream.opensearch.acl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.bucket.global.GlobalAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.SignificantTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.SignificantTextAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;

/**
 * Adds the ACL access query to every search that reaches an ACL protected index, and to the background filter of
 * significant terms aggregations. Explain, suggest, global and significant text aggregations are refused.
 */
public final class AclSearchFilter implements ActionFilter {

    /** Runs after the Security plugin's filter, which uses {@link Integer#MIN_VALUE}. */
    public static final int ORDER = 1000;

    private final Supplier<ClusterState> clusterState;
    private final CallerPrincipalResolver principals;
    private final AclFields fields;

    /**
     * Creates the filter.
     *
     * @param clusterState supplies the current cluster state
     * @param principals resolves the caller's principal keys
     * @param fields the ACL field names
     */
    public AclSearchFilter(Supplier<ClusterState> clusterState, CallerPrincipalResolver principals, AclFields fields) {
        this.clusterState = clusterState;
        this.principals = principals;
        this.fields = fields;
    }

    @Override
    public int order() {
        return ORDER;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
            Task task,
            String action,
            Request request,
            ActionRequestMetadata<Request, Response> actionRequestMetadata,
            ActionListener<Response> listener,
            ActionFilterChain<Request, Response> chain) {
        if (!SearchAction.NAME.equals(action) || !(request instanceof SearchRequest searchRequest)) {
            chain.proceed(task, action, request, listener);
            return;
        }
        Scope scope = scope(actionRequestMetadata.resolvedIndices());
        if (scope.unprotected()) {
            chain.proceed(task, action, request, listener);
            return;
        }
        SearchSourceBuilder source = searchRequest.source() == null ? new SearchSourceBuilder() : searchRequest.source();
        String rejection = unsupported(source);
        if (rejection != null) {
            listener.onFailure(new OpenSearchStatusException(rejection, RestStatus.BAD_REQUEST));
            return;
        }
        principals.resolve(ActionListener.wrap(keys -> {
            QueryBuilder access = scope.protectedIndices() == null
                    ? AclQueries.access(fields, keys)
                    : AclQueries.accessForIndices(fields, keys, scope.protectedIndices());
            source.query(AclQueries.restrict(source.query(), access));
            if (source.aggregations() != null) {
                limitBackgrounds(source.aggregations().getAggregatorFactories(), access);
            }
            searchRequest.source(source);
            chain.proceed(task, action, request, listener);
        }, listener::onFailure));
    }

    private Scope scope(OptionallyResolvedIndices resolved) {
        if (!(resolved instanceof ResolvedIndices known) || !known.remote().asRawExpressions().isEmpty()) {
            return Scope.ALL;
        }
        ClusterState state = clusterState.get();
        List<String> protectedIndices = new ArrayList<>();
        for (String name : known.local().namesOfIndices(state)) {
            IndexMetadata index = state.metadata().index(name);
            if (index != null && AclSettings.INDEX_ACL_ENABLED.get(index.getSettings())) {
                protectedIndices.add(name);
            }
        }
        return protectedIndices.isEmpty() ? Scope.NONE : new Scope(protectedIndices);
    }

    private static void limitBackgrounds(Collection<AggregationBuilder> aggregations, QueryBuilder access) {
        for (AggregationBuilder aggregation : aggregations) {
            if (aggregation instanceof SignificantTermsAggregationBuilder terms) {
                terms.backgroundFilter(AclQueries.restrict(terms.backgroundFilter(), access));
            }
            limitBackgrounds(aggregation.getSubAggregations(), access);
        }
    }

    private static String unsupported(SearchSourceBuilder source) {
        if (Boolean.TRUE.equals(source.explain())) {
            return "explain is not supported on ACL protected indices";
        }
        if (source.suggest() != null) {
            return "suggest is not supported on ACL protected indices";
        }
        if (source.aggregations() != null) {
            for (AggregationBuilder aggregation : source.aggregations().getAggregatorFactories()) {
                if (aggregation instanceof GlobalAggregationBuilder) {
                    return "global aggregations are not supported on ACL protected indices";
                }
            }
            if (containsSignificantText(source.aggregations().getAggregatorFactories())) {
                return "significant text aggregations are not supported on ACL protected indices";
            }
        }
        return null;
    }

    private static boolean containsSignificantText(Collection<AggregationBuilder> aggregations) {
        for (AggregationBuilder aggregation : aggregations) {
            if (aggregation instanceof SignificantTextAggregationBuilder
                    || containsSignificantText(aggregation.getSubAggregations())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Which indices of a search are protected.
     *
     * @param protectedIndices concrete protected index names, or null when every index is treated as protected
     */
    private record Scope(List<String> protectedIndices) {

        static final Scope ALL = new Scope(null);
        static final Scope NONE = new Scope(List.of());

        boolean unprotected() {
            return protectedIndices != null && protectedIndices.isEmpty();
        }
    }
}
