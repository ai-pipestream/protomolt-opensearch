package ai.pipestream.opensearch.acl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.apache.lucene.util.SetOnce;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.identity.PluginSubject;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.transport.client.Client;

/**
 * Stores the principal keys each caller holds beyond those of its login, in the plugin's system index, keyed by the
 * Security plugin user name.
 */
public final class PrincipalStore {

    /** System index holding one document per caller. */
    public static final String INDEX = ".protomolt-acl-principals";

    /** Field of a principals document holding the keys. */
    public static final String KEYS_FIELD = "keys";

    private final Supplier<Client> client;
    private final Supplier<ThreadContext> threadContext;
    private final SetOnce<PluginSubject> subject = new SetOnce<>();

    /**
     * Creates the store.
     *
     * @param client supplies the node client
     * @param threadContext supplies the node's thread context
     */
    public PrincipalStore(Supplier<Client> client, Supplier<ThreadContext> threadContext) {
        this.client = client;
        this.threadContext = threadContext;
    }

    /**
     * Sets the subject the store runs its index requests as.
     *
     * @param pluginSubject the plugin's subject
     */
    public void assignSubject(PluginSubject pluginSubject) {
        subject.set(pluginSubject);
    }

    /**
     * Reads the stored keys of a caller. A caller without a document, or a store whose index does not exist yet,
     * has no keys.
     *
     * @param user the Security plugin user name
     * @param listener receives the keys
     */
    public void keys(String user, ActionListener<List<String>> listener) {
        runAsPlugin(listener, wrapped -> client.get().get(new GetRequest(INDEX, user).realtime(true), ActionListener.wrap(
                response -> wrapped.onResponse(response.isExists() ? keysOf(response.getSourceAsMap()) : List.of()),
                e -> {
                    if (e instanceof IndexNotFoundException) {
                        wrapped.onResponse(List.of());
                    } else {
                        wrapped.onFailure(e);
                    }
                })));
    }

    /**
     * Replaces the stored keys of a caller and refreshes the store so the next lookup sees them.
     *
     * @param user the Security plugin user name
     * @param keys the caller's keys
     * @param listener completes when the keys are stored
     */
    public void put(String user, Collection<String> keys, ActionListener<Void> listener) {
        IndexRequest request = new IndexRequest(INDEX).id(user).source(Map.of(KEYS_FIELD, List.copyOf(keys)))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        runAsPlugin(listener, wrapped -> client.get().index(request, ActionListener.wrap(
                response -> wrapped.onResponse(null),
                wrapped::onFailure)));
    }

    private <T> void runAsPlugin(ActionListener<T> listener, Consumer<ActionListener<T>> call) {
        ThreadContext context = threadContext.get();
        ActionListener<T> restoring = new ContextPreservingActionListener<>(context.newRestorableContext(false), listener);
        PluginSubject pluginSubject = subject.get();
        if (pluginSubject == null) {
            listener.onFailure(new IllegalStateException("the plugin subject is not assigned"));
            return;
        }
        try {
            pluginSubject.runAs(() -> call.accept(restoring));
        } catch (RuntimeException e) {
            restoring.onFailure(e);
        }
    }

    private static List<String> keysOf(Map<String, Object> source) {
        List<String> keys = new ArrayList<>();
        if (source != null && source.get(KEYS_FIELD) instanceof Collection<?> values) {
            for (Object value : values) {
                if (value instanceof String key) {
                    keys.add(key);
                }
            }
        }
        return keys;
    }
}
