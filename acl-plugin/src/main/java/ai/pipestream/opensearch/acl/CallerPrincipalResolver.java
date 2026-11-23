package ai.pipestream.opensearch.acl;

import java.util.Locale;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.function.Supplier;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;

/**
 * Resolves the caller's principal keys: the user name and backend roles from the Security plugin, plus the keys
 * stored for the user in the {@link PrincipalStore}. Keys are lower-cased.
 */
public final class CallerPrincipalResolver {

    private final Supplier<ThreadContext> threadContext;
    private final PrincipalStore store;

    /**
     * Creates the resolver.
     *
     * @param threadContext supplies the node's thread context
     * @param store the principal store
     */
    public CallerPrincipalResolver(Supplier<ThreadContext> threadContext, PrincipalStore store) {
        this.threadContext = threadContext;
        this.store = store;
    }

    /**
     * Resolves the current caller's keys. A caller with no authenticated user has none.
     *
     * @param listener receives the keys
     */
    public void resolve(ActionListener<Set<String>> listener) {
        String userInfo = threadContext.get().getTransient(CallerPrincipals.SECURITY_USER_INFO_TRANSIENT);
        Set<String> login = CallerPrincipals.fromSecurityUserInfo(userInfo);
        if (login.isEmpty()) {
            listener.onResponse(Set.of());
            return;
        }
        String user = login.iterator().next();
        store.keys(user, ActionListener.wrap(stored -> {
            Set<String> keys = new LinkedHashSet<>();
            for (String key : login) {
                keys.add(normalize(key));
            }
            for (String key : stored) {
                keys.add(normalize(key));
            }
            listener.onResponse(keys);
        }, listener::onFailure));
    }

    /**
     * Normalizes a principal key for matching.
     *
     * @param key the key
     * @return the lower-cased key
     */
    public static String normalize(String key) {
        return key.toLowerCase(Locale.ROOT);
    }
}
