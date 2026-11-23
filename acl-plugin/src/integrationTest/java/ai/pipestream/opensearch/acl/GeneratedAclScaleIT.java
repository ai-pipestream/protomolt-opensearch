package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Indexes generated documents with random allow, deny and gate keys and checks, for callers holding from a few to
 * tens of thousands of keys, that searches and gets return exactly the documents the ACL rule allows. Records
 * search and get timings to {@code build/reports/acl-scale/timings.txt}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GeneratedAclScaleIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PASSWORD = "Us3r-Scale-Test!pw";
    private static final int DOCUMENTS = 20_000;
    private static final int GROUPS = 50_000;
    private static final int POPULAR_GROUPS = 200;
    private static final int MAX_TERMS_COUNT = 65_536;
    private static final int TIMING_RUNS = 20;
    private static final String MAPPING = """
            {
              "settings": { "index.protomolt.acl.enabled": %s, "number_of_shards": 2, "number_of_replicas": 0 },
              "mappings": { "properties": {
                "doc_id": { "type": "keyword" },
                "acl_allow": { "type": "keyword" },
                "acl_deny": { "type": "keyword" },
                "acl_complete": { "type": "boolean" },
                "acl_gates": { "type": "nested", "properties": { "allow": { "type": "keyword" } } }
              } }
            }
            """;

    private record Doc(String id, boolean complete, Set<String> allow, Set<String> deny, List<Set<String>> gates) {
    }

    private final Random random = new Random(20261123L);
    private final List<Doc> docs = new ArrayList<>();
    private final Map<String, Set<String>> callers = new LinkedHashMap<>();
    private final List<String> timings = new ArrayList<>();
    private OpenSearchNode node;

    @BeforeAll
    void startNode() throws Exception {
        node = OpenSearchNode.start();
        node.admin("PUT", "/scale-acl", MAPPING.formatted("true"));
        node.admin("PUT", "/scale-open", MAPPING.formatted("false"));

        for (int i = 0; i < DOCUMENTS; i++) {
            docs.add(randomDoc("doc-" + i));
        }
        for (int from = 0; from < DOCUMENTS; from += 2_000) {
            StringBuilder bulk = new StringBuilder();
            for (Doc doc : docs.subList(from, Math.min(DOCUMENTS, from + 2_000))) {
                String source = JSON.writeValueAsString(source(doc));
                for (String index : List.of("scale-acl", "scale-open")) {
                    bulk.append(JSON.writeValueAsString(Map.of("index", Map.of("_index", index, "_id", doc.id()))))
                            .append('\n').append(source).append('\n');
                }
            }
            assertThat(node.admin("POST", "/_bulk", bulk.toString()).path("errors").asBoolean(true))
                    .as("bulk errors").isFalse();
        }
        node.admin("POST", "/scale-acl,scale-open/_refresh", null);

        callers.put("scale-few", randomKeys(5, 3));
        callers.put("scale-hundreds", randomKeys(500, 50));
        callers.put("scale-thousands", randomKeys(5_000, 100));
        callers.put("scale-max", randomKeys(MAX_TERMS_COUNT - 1, POPULAR_GROUPS));
        callers.put("scale-over", randomKeys(MAX_TERMS_COUNT + 10, POPULAR_GROUPS));

        node.admin("PUT", "/_plugins/_security/api/roles/scale_reader", """
                {"cluster_permissions":["cluster_composite_ops_ro"],
                 "index_permissions":[{"index_patterns":["scale-*"],"allowed_actions":["read"]}]}
                """);
        for (Map.Entry<String, Set<String>> caller : callers.entrySet()) {
            node.admin("PUT", "/_plugins/_security/api/internalusers/" + caller.getKey(),
                    "{\"password\":\"" + PASSWORD + "\",\"backend_roles\":[]}");
            node.admin("PUT", "/_plugins/protomolt_acl/principals/" + caller.getKey(),
                    "{\"keys\":" + JSON.writeValueAsString(caller.getValue()) + "}");
        }
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/scale_reader",
                "{\"users\":" + JSON.writeValueAsString(callers.keySet()) + "}");
    }

    @AfterAll
    void stopNode() throws IOException {
        if (node != null) {
            node.close();
        }
        Path report = Path.of("build", "reports", "acl-scale", "timings.txt");
        Files.createDirectories(report.getParent());
        Files.write(report, timings, StandardCharsets.UTF_8);
    }

    private Doc randomDoc(String id) {
        boolean complete = random.nextInt(100) >= 3;
        Set<String> allow = new HashSet<>();
        int allowCount = 1 + random.nextInt(5);
        for (int i = 0; i < allowCount; i++) {
            allow.add(randomGroup());
        }
        Set<String> deny = new HashSet<>();
        if (random.nextInt(100) < 15) {
            deny.add(randomGroup());
        }
        List<Set<String>> gates = new ArrayList<>();
        int gateCount = random.nextInt(100) < 70 ? 0 : 1 + random.nextInt(2);
        for (int g = 0; g < gateCount; g++) {
            Set<String> gate = new HashSet<>();
            int keys = 1 + random.nextInt(3);
            for (int i = 0; i < keys; i++) {
                gate.add(randomGroup());
            }
            gates.add(gate);
        }
        return new Doc(id, complete, allow, deny, gates);
    }

    private String randomGroup() {
        int group = random.nextBoolean() ? random.nextInt(POPULAR_GROUPS) : random.nextInt(GROUPS);
        return "grp:g" + group;
    }

    private Set<String> randomKeys(int count, int popular) {
        Set<String> keys = new HashSet<>();
        while (keys.size() < Math.min(popular, count)) {
            keys.add("grp:g" + random.nextInt(POPULAR_GROUPS));
        }
        List<Integer> groups = new ArrayList<>();
        for (int i = 0; i < GROUPS; i++) {
            groups.add(i);
        }
        java.util.Collections.shuffle(groups, random);
        for (int i = 0; i < GROUPS && keys.size() < count; i++) {
            keys.add("grp:g" + groups.get(i));
        }
        for (int i = 0; keys.size() < count; i++) {
            keys.add("grp:extra" + i);
        }
        return keys;
    }

    private static Map<String, Object> source(Doc doc) {
        List<Map<String, Object>> gates = new ArrayList<>();
        for (Set<String> gate : doc.gates()) {
            gates.add(Map.of("allow", List.copyOf(gate)));
        }
        return Map.of(
                "doc_id", doc.id(),
                "acl_complete", doc.complete(),
                "acl_allow", List.copyOf(doc.allow()),
                "acl_deny", List.copyOf(doc.deny()),
                "acl_gates", gates);
    }

    private static boolean readable(Doc doc, Set<String> keys) {
        if (!doc.complete() || doc.deny().stream().anyMatch(keys::contains)
                || doc.allow().stream().noneMatch(keys::contains)) {
            return false;
        }
        return doc.gates().stream().allMatch(gate -> gate.stream().anyMatch(keys::contains));
    }

    private TreeSet<String> expected(String user) {
        Set<String> keys = new HashSet<>(callers.get(user));
        keys.add(user);
        TreeSet<String> ids = new TreeSet<>();
        for (Doc doc : docs) {
            if (readable(doc, keys)) {
                ids.add(doc.id());
            }
        }
        return ids;
    }

    private TreeSet<String> searchAllIds(String user, String index) throws IOException, InterruptedException {
        TreeSet<String> ids = new TreeSet<>();
        String after = null;
        while (true) {
            String body = "{\"size\":5000,\"_source\":false,\"sort\":[{\"doc_id\":\"asc\"}]"
                    + (after == null ? "" : ",\"search_after\":[" + JSON.writeValueAsString(after) + "]") + "}";
            OpenSearchNode.Response response = node.request(user, PASSWORD, "POST", "/" + index + "/_search", body);
            assertThat(response.status()).as(user + ": " + response.body()).isEqualTo(200);
            JsonNode hits = response.body().path("hits").path("hits");
            if (hits.isEmpty()) {
                return ids;
            }
            for (JsonNode hit : hits) {
                ids.add(hit.path("_id").asText());
                after = hit.path("sort").get(0).asText();
            }
        }
    }

    @Test
    void generatedDataHasEveryOutcome() {
        Set<String> keys = callers.get("scale-thousands");
        long incomplete = docs.stream().filter(doc -> !doc.complete()).count();
        long denied = docs.stream().filter(doc -> doc.complete() && doc.allow().stream().anyMatch(keys::contains)
                && doc.deny().stream().anyMatch(keys::contains)).count();
        long gated = docs.stream().filter(doc -> doc.complete() && doc.allow().stream().anyMatch(keys::contains)
                && doc.deny().stream().noneMatch(keys::contains)
                && !doc.gates().stream().allMatch(gate -> gate.stream().anyMatch(keys::contains))).count();
        assertThat(incomplete).isPositive();
        assertThat(denied).as("allowed but denied").isPositive();
        assertThat(gated).as("allowed but stopped by a gate").isPositive();
        assertThat(expected("scale-thousands")).isNotEmpty();
    }

    @Test
    void searchReturnsExactlyTheReadableDocumentsForEveryCaller() throws Exception {
        for (String user : List.of("scale-few", "scale-hundreds", "scale-thousands", "scale-max")) {
            TreeSet<String> expected = expected(user);
            assertThat(searchAllIds(user, "scale-acl")).as(user + " (" + callers.get(user).size() + " keys)")
                    .isEqualTo(expected);
            timings.add(user + ": " + callers.get(user).size() + " keys, " + expected.size() + " of " + DOCUMENTS
                    + " documents readable");
        }
    }

    @Test
    void getMatchesTheRuleForASampleOfDocuments() throws Exception {
        for (String user : List.of("scale-hundreds", "scale-thousands")) {
            TreeSet<String> expected = expected(user);
            for (int i = 0; i < DOCUMENTS; i += 97) {
                String id = docs.get(i).id();
                int status = node.request(user, PASSWORD, "GET", "/scale-acl/_doc/" + id, null).status();
                assertThat(status).as(user + " " + id).isEqualTo(expected.contains(id) ? 200 : 404);
            }
        }
    }

    @Test
    void callerOverTheTermsLimitIsRefusedAndSeesNothing() throws Exception {
        OpenSearchNode.Response response = node.request("scale-over", PASSWORD, "POST", "/scale-acl/_search",
                "{\"size\":10}");
        timings.add("scale-over: " + callers.get("scale-over").size() + " keys, search answered " + response.status()
                + " " + response.body().path("error").path("root_cause").path(0).path("reason").asText());
        assertThat(response.status()).isNotEqualTo(200);
        assertThat(response.body().path("hits").path("hits").isEmpty()).isTrue();
        assertThat(response.body().toString()).doesNotContain("doc-");
    }

    @Test
    void recordTimings() throws Exception {
        for (String user : List.of("scale-few", "scale-hundreds", "scale-thousands", "scale-max")) {
            timings.add(user + " search scale-acl: " + medianMillis(user, "POST", "/scale-acl/_search", QUERY));
            timings.add(user + " search scale-open: " + medianMillis(user, "POST", "/scale-open/_search", QUERY));
            timings.add(user + " get scale-acl: " + medianMillis(user, "GET", "/scale-acl/_doc/doc-7", null));
            timings.add(user + " get scale-open: " + medianMillis(user, "GET", "/scale-open/_doc/doc-7", null));
        }
    }

    private static final String QUERY = "{\"size\":10,\"track_total_hits\":true,\"query\":{\"match_all\":{}}}";

    private String medianMillis(String user, String method, String path, String body) throws Exception {
        node.request(user, PASSWORD, method, path, body);
        long[] runs = new long[TIMING_RUNS];
        for (int i = 0; i < TIMING_RUNS; i++) {
            long start = System.nanoTime();
            OpenSearchNode.Response response = node.request(user, PASSWORD, method, path, body);
            runs[i] = System.nanoTime() - start;
            assertThat(response.status()).isIn(200, 404);
        }
        Arrays.sort(runs);
        return String.format(java.util.Locale.ROOT, "median %.1f ms, max %.1f ms over %d runs",
                runs[TIMING_RUNS / 2] / 1e6, runs[TIMING_RUNS - 1] / 1e6, TIMING_RUNS);
    }
}
