package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensearch.common.unit.TimeValue;

class PrincipalKeyCacheTest {

    @Test
    void keepsKeysUntilInvalidated() {
        PrincipalKeyCache cache = new PrincipalKeyCache(TimeValue.timeValueMinutes(5), 10);
        cache.put("eve", List.of("grp:space"), cache.generation());

        assertThat(cache.get("eve")).containsExactly("grp:space");

        cache.invalidate("eve");
        assertThat(cache.get("eve")).isNull();
    }

    @Test
    void dropsKeysReadBeforeAnInvalidation() {
        PrincipalKeyCache cache = new PrincipalKeyCache(TimeValue.timeValueMinutes(5), 10);
        long generation = cache.generation();
        cache.invalidate("eve");

        cache.put("eve", List.of("grp:old"), generation);

        assertThat(cache.get("eve")).isNull();
    }

    @Test
    void expiresEntries() throws InterruptedException {
        PrincipalKeyCache cache = new PrincipalKeyCache(TimeValue.timeValueMillis(20), 10);
        cache.put("eve", List.of("grp:space"), cache.generation());

        Thread.sleep(100);

        assertThat(cache.get("eve")).isNull();
    }

    @Test
    void zeroTtlCachesNothing() {
        PrincipalKeyCache cache = new PrincipalKeyCache(TimeValue.ZERO, 10);
        cache.put("eve", List.of("grp:space"), cache.generation());

        assertThat(cache.get("eve")).isNull();
        assertThat(cache.size()).isZero();
    }

    @Test
    void keepsAtMostTheConfiguredNumberOfCallers() {
        PrincipalKeyCache cache = new PrincipalKeyCache(TimeValue.timeValueMinutes(5), 2);
        cache.put("a", List.of(), cache.generation());
        cache.put("b", List.of(), cache.generation());
        cache.put("c", List.of(), cache.generation());

        assertThat(cache.size()).isEqualTo(2);
        assertThat(cache.get("a")).isNull();
    }
}
