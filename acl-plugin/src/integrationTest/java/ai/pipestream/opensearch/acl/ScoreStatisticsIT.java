package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Checks what a caller can learn about hidden documents from index statistics: significant terms backgrounds are
 * limited to readable documents, and scores still use statistics of the whole index. Compares with the Security
 * plugin's document-level security and records the observed numbers to
 * {@code build/reports/acl-scale/score-statistics.txt}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ScoreStatisticsIT {

    private static final String PASSWORD = "Us3r-Stats-Test!pw";
    private static final int HIDDEN = 50;
    private static final String MAPPING = """
            {
              "settings": { "index.protomolt.acl.enabled": %s, "number_of_shards": 1, "number_of_replicas": 0 },
              "mappings": { "properties": {
                "body": { "type": "text" },
                "tag": { "type": "keyword" },
                "acl_allow": { "type": "keyword" },
                "acl_complete": { "type": "boolean" }
              } }
            }
            """;
    private static final String SIGNIFICANT = """
            {"size":0,"query":{"match_all":{}},"aggs":{
              "tags":{"significant_terms":{"field":"tag","min_doc_count":1}},
              "by_tag":{"terms":{"field":"tag"},"aggs":{
                "nested_tags":{"significant_terms":{"field":"tag","min_doc_count":1}}}}}}
            """;
    private static final String SIGNIFICANT_TEXT = """
            {"size":0,"query":{"match_all":{}},"aggs":{
              "words":{"significant_text":{"field":"body","min_doc_count":1}}}}
            """;
    private static final String BUDGET = "{\"query\":{\"match\":{\"body\":\"budget\"}}}";

    private final List<String> report = new ArrayList<>();
    private OpenSearchNode node;

    @BeforeAll
    void startNode() throws Exception {
        node = OpenSearchNode.start();
        node.admin("PUT", "/stats-acl", MAPPING.formatted("true"));
        node.admin("PUT", "/stats-dls", MAPPING.formatted("false"));
        node.admin("PUT", "/stats-visible-only", MAPPING.formatted("false"));
        String visible = "{\"body\":\"budget plan for the team\",\"tag\":\"plan\",\"acl_allow\":[\"grp:viewer\"],"
                + "\"acl_complete\":true}";
        String hidden = "{\"body\":\"budget secret merger\",\"tag\":\"merger\",\"acl_allow\":[\"grp:board\"],"
                + "\"acl_complete\":true}";
        StringBuilder bulk = new StringBuilder();
        for (String index : List.of("stats-acl", "stats-dls", "stats-visible-only")) {
            bulk.append("{\"index\":{\"_index\":\"").append(index).append("\",\"_id\":\"visible\"}}\n")
                    .append(visible).append('\n');
        }
        for (int i = 0; i < HIDDEN; i++) {
            for (String index : List.of("stats-acl", "stats-dls")) {
                bulk.append("{\"index\":{\"_index\":\"").append(index).append("\",\"_id\":\"hidden-").append(i)
                        .append("\"}}\n").append(hidden).append('\n');
            }
        }
        node.admin("POST", "/_bulk?refresh=true", bulk.toString());
        node.admin("PUT", "/_plugins/_security/api/roles/stats_reader", """
                {"cluster_permissions":["cluster_composite_ops_ro"],
                 "index_permissions":[
                   {"index_patterns":["stats-acl","stats-visible-only"],"allowed_actions":["read"]},
                   {"index_patterns":["stats-dls"],"allowed_actions":["read"],
                    "dls":"{\\"terms\\":{\\"acl_allow\\":[\\"grp:viewer\\"]}}"}
                 ]}
                """);
        node.admin("PUT", "/_plugins/_security/api/internalusers/viewer",
                "{\"password\":\"" + PASSWORD + "\",\"backend_roles\":[\"grp:viewer\"]}");
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/stats_reader", "{\"users\":[\"viewer\"]}");
    }

    @AfterAll
    void stopNode() throws IOException {
        if (node != null) {
            node.close();
        }
        Path file = Path.of("build", "reports", "acl-scale", "score-statistics.txt");
        Files.createDirectories(file.getParent());
        Files.write(file, report, StandardCharsets.UTF_8);
    }

    private JsonNode search(String index, String body) throws IOException, InterruptedException {
        OpenSearchNode.Response response = node.request("viewer", PASSWORD, "POST", "/" + index + "/_search", body);
        assertThat(response.status()).as(index + ": " + response.body()).isEqualTo(200);
        return response.body();
    }

    private static List<String> keys(JsonNode aggregation) {
        List<String> keys = new ArrayList<>();
        for (JsonNode bucket : aggregation.path("buckets")) {
            keys.add(bucket.path("key").asText());
        }
        return keys;
    }

    @Test
    void significantTermsOnlyCountReadableDocuments() throws Exception {
        JsonNode aggregations = search("stats-acl", SIGNIFICANT).path("aggregations");
        report.add("plugin significant_terms: bg_count " + aggregations.path("tags").path("bg_count")
                + ", buckets " + aggregations.path("tags").path("buckets"));
        assertThat(aggregations.path("tags").path("bg_count").asLong()).isEqualTo(1);
        assertThat(keys(aggregations.path("tags"))).as("nothing stands out against readable documents only").isEmpty();
        JsonNode nested = aggregations.path("by_tag").path("buckets").path(0).path("nested_tags");
        assertThat(nested.path("bg_count").asLong()).isEqualTo(1);
        assertThat(aggregations.toString()).doesNotContain("merger");
    }

    @Test
    void significantTextIsRejected() throws Exception {
        OpenSearchNode.Response response =
                node.request("viewer", PASSWORD, "POST", "/stats-acl/_search", SIGNIFICANT_TEXT);
        assertThat(response.status()).isEqualTo(400);
        assertThat(response.body().toString()).doesNotContain("merger", "secret");
    }

    @Test
    void builtInDlsSignificantAggregationsCountHiddenDocuments() throws Exception {
        JsonNode terms = search("stats-dls", SIGNIFICANT).path("aggregations").path("tags");
        JsonNode text = search("stats-dls", SIGNIFICANT_TEXT).path("aggregations").path("words");
        report.add("dls significant_terms: bg_count " + terms.path("bg_count") + ", buckets " + terms.path("buckets"));
        report.add("dls significant_text: bg_count " + text.path("bg_count") + ", buckets " + text.path("buckets"));
        assertThat(terms.path("bg_count").asLong()).isEqualTo(HIDDEN + 1);
        assertThat(text.path("bg_count").asLong()).isEqualTo(HIDDEN + 1);
        assertThat(keys(terms)).doesNotContain("merger");
    }

    @Test
    void scoresStillReflectHiddenDocuments() throws Exception {
        double alone = search("stats-visible-only", BUDGET).path("hits").path("max_score").asDouble();
        double plugin = search("stats-acl", BUDGET).path("hits").path("max_score").asDouble();
        double dls = search("stats-dls", BUDGET).path("hits").path("max_score").asDouble();
        report.add("score of the readable document for 'budget': alone " + alone + ", plugin " + plugin
                + ", dls " + dls);
        assertThat(search("stats-acl", BUDGET).path("hits").path("total").path("value").asLong()).isEqualTo(1);
        assertThat(plugin).as("plugin score uses index-wide statistics").isLessThan(alone);
        assertThat(dls - 1.0).as("dls score uses index-wide statistics").isLessThan(alone);
    }
}
