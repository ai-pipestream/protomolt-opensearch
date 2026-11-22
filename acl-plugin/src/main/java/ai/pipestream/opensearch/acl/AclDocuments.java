package ai.pipestream.opensearch.acl;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Evaluates a document's ACL fields, read from its source, against the caller's principals.
 */
public final class AclDocuments {

    private AclDocuments() {
    }

    /**
     * Returns whether the caller may read the document: the ACL is complete, the allow field holds one of the
     * caller's principals, every gate holds one of them, and the deny field holds none of them.
     *
     * @param fields the ACL field names
     * @param source the document source, or null when it is not available
     * @param principals the caller's principal keys, lower-cased
     * @return true when the caller may read the document
     */
    public static boolean allows(AclFields fields, Map<String, Object> source, Set<String> principals) {
        if (source == null || principals.isEmpty()) {
            return false;
        }
        Object complete = source.get(fields.complete());
        if (!Boolean.TRUE.equals(complete) && !"true".equals(complete)) {
            return false;
        }
        if (matchesAny(source.get(fields.deny()), principals) || !matchesAny(source.get(fields.allow()), principals)) {
            return false;
        }
        Object gates = source.get(fields.gates());
        if (gates == null) {
            return true;
        }
        for (Object gate : asCollection(gates)) {
            if (!(gate instanceof Map<?, ?> gateMap) || !matchesAny(gateMap.get(fields.gateAllow()), principals)) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchesAny(Object values, Set<String> principals) {
        if (values == null) {
            return false;
        }
        for (Object value : asCollection(values)) {
            if (value instanceof String key && principals.contains(CallerPrincipalResolver.normalize(key))) {
                return true;
            }
        }
        return false;
    }

    private static Collection<?> asCollection(Object value) {
        return value instanceof Collection<?> collection ? collection : List.of(value);
    }
}
