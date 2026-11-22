package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class AclDocumentsTest {

    private static final AclFields FIELDS = new AclFields("acl_allow", "acl_gates", "allow", "acl_complete");

    @Test
    void allowsWhenAllowAndEveryGateMatch() {
        Map<String, Object> source = Map.of(
                "acl_complete", true,
                "acl_allow", List.of("grp:space"),
                "acl_gates", List.of(Map.of("allow", List.of("grp:legal")), Map.of("allow", "bob")));

        assertThat(AclDocuments.allows(FIELDS, source, Set.of("bob", "grp:space", "grp:legal"))).isTrue();
        assertThat(AclDocuments.allows(FIELDS, source, Set.of("alice", "grp:space", "grp:legal"))).isFalse();
    }

    @Test
    void deniesIncompleteOrMissingAcl() {
        assertThat(AclDocuments.allows(FIELDS, Map.of("acl_allow", "alice"), Set.of("alice"))).isFalse();
        assertThat(AclDocuments.allows(FIELDS, Map.of("acl_complete", false, "acl_allow", "alice"), Set.of("alice")))
                .isFalse();
        assertThat(AclDocuments.allows(FIELDS, Map.of("acl_complete", true), Set.of("alice"))).isFalse();
        assertThat(AclDocuments.allows(FIELDS, null, Set.of("alice"))).isFalse();
    }

    @Test
    void deniesWithoutPrincipals() {
        assertThat(AclDocuments.allows(FIELDS, Map.of("acl_complete", true, "acl_allow", "alice"), Set.of()))
                .isFalse();
    }

    @Test
    void deniesMalformedGate() {
        Map<String, Object> source = Map.of("acl_complete", true, "acl_allow", "alice", "acl_gates", List.of("alice"));

        assertThat(AclDocuments.allows(FIELDS, source, Set.of("alice"))).isFalse();
    }
}
