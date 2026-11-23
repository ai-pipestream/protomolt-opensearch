package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CallerPrincipalsTest {

    @Test
    void readsUserAndBackendRoles() {
        assertThat(CallerPrincipals.fromSecurityUserInfo("alice|grp:legal,grp:space|own_index,acl_reader||WRITE"))
                .containsExactly("alice", "grp:legal", "grp:space");
    }

    @Test
    void ignoresMappedSecurityRoles() {
        assertThat(CallerPrincipals.fromSecurityUserInfo("alice||all_access|tenant|WRITE")).containsExactly("alice");
    }

    @Test
    void unescapesPipes() {
        assertThat(CallerPrincipals.fromSecurityUserInfo("a\\|b|r\\|1,r2|x"))
                .containsExactly("a|b", "r|1", "r2");
    }

    @Test
    void returnsNothingWithoutUser() {
        assertThat(CallerPrincipals.fromSecurityUserInfo(null)).isEmpty();
        assertThat(CallerPrincipals.fromSecurityUserInfo("")).isEmpty();
        assertThat(CallerPrincipals.fromSecurityUserInfo("|grp:legal|")).isEmpty();
    }

    @Test
    void readsNameOnly() {
        assertThat(CallerPrincipals.fromSecurityUserInfo("bob")).containsExactly("bob");
    }
}
