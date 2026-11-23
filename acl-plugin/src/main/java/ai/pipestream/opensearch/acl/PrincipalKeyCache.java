package ai.pipestream.opensearch.acl;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.opensearch.common.cache.Cache;
import org.opensearch.common.cache.CacheBuilder;
import org.opensearch.common.unit.TimeValue;

/**
 * Holds the stored keys of callers on this node for a limited time.
 */
final class PrincipalKeyCache {

    private final Cache<String, List<String>> cache;
    private final AtomicLong generation = new AtomicLong();

    /**
     * Creates the cache.
     *
     * @param ttl how long an entry is kept after it is written; zero turns the cache off
     * @param maxEntries how many callers are kept at most
     */
    PrincipalKeyCache(TimeValue ttl, long maxEntries) {
        this.cache = ttl.nanos() > 0 && maxEntries > 0
                ? CacheBuilder.<String, List<String>>builder()
                        .setExpireAfterWrite(ttl)
                        .setMaximumWeight(maxEntries)
                        .build()
                : null;
    }

    /**
     * Returns the cached keys of a caller.
     *
     * @param user the Security plugin user name
     * @return the keys, or null when none are cached
     */
    List<String> get(String user) {
        return cache == null ? null : cache.get(user);
    }

    /**
     * Returns a value that changes whenever an entry is invalidated; pass it to {@link #put} with keys read after
     * this call.
     *
     * @return the current generation
     */
    long generation() {
        return generation.get();
    }

    /**
     * Caches the keys of a caller unless an entry was invalidated since {@code readGeneration}.
     *
     * @param user the Security plugin user name
     * @param keys the keys read from the store
     * @param readGeneration the generation taken before the keys were read
     */
    void put(String user, List<String> keys, long readGeneration) {
        if (cache != null && generation.get() == readGeneration) {
            cache.put(user, List.copyOf(keys));
            if (generation.get() != readGeneration) {
                cache.invalidate(user);
            }
        }
    }

    /**
     * Drops the cached keys of a caller.
     *
     * @param user the Security plugin user name
     */
    void invalidate(String user) {
        generation.incrementAndGet();
        if (cache != null) {
            cache.invalidate(user);
        }
    }

    /**
     * Returns how many callers are cached.
     *
     * @return the number of entries
     */
    int size() {
        return cache == null ? 0 : cache.count();
    }
}
