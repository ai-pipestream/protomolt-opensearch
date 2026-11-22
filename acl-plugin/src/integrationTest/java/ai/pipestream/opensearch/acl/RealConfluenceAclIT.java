package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Indexes protomolt's document security for real Confluence pages and checks, for every recorded caller and page,
 * that the plugin and the Security plugin's document-level security both return exactly what protomolt's own access
 * policy decides.
 */
class RealConfluenceAclIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PASSWORD = "Us3r-Real-Test!pw";
    private static final String MAPPING = """
            {
              "settings": { "index.protomolt.acl.enabled": %s, "number_of_replicas": 0 },
              "mappings": { "properties": {
                "acl_allow": { "type": "keyword" },
                "acl_deny": { "type": "keyword" },
                "acl_complete": { "type": "boolean" },
                "acl_gates": { "type": "nested", "properties": {
                  "source": { "type": "keyword" }, "allow": { "type": "keyword" } } }
              } }
            }
            """;
    private static final String DLS_QUERY = """
            {"bool":{
              "filter":[
                {"term":{"acl_complete":true}},
                {"terms":{"acl_allow":{"index":"real-dls-principals","id":"${user.name}","path":"keys"}}}
              ],
              "must_not":[
                {"terms":{"acl_deny":{"index":"real-dls-principals","id":"${user.name}","path":"keys"}}},
                {"nested":{"path":"acl_gates","query":{"bool":{"must_not":[
                  {"terms":{"acl_gates.allow":{"index":"real-dls-principals","id":"${user.name}","path":"keys"}}}
                ]}}}}
              ]
            }}
            """;

    /** Test user name per recorded caller, with protomolt's decisions. */
    private static final Map<String, JsonNode> CALLERS = new LinkedHashMap<>();
    private static final List<String> PAGE_IDS = new ArrayList<>();
    private static OpenSearchNode node;

    @BeforeAll
    static void startNode() throws Exception {
        node = OpenSearchNode.start();
        node.admin("PUT", "/real-plugin", MAPPING.formatted("true"));
        node.admin("PUT", "/real-dls", MAPPING.formatted("false"));
        node.admin("PUT", "/real-dls-principals", "{\"settings\":{\"number_of_replicas\":0}}");

        StringBuilder bulk = new StringBuilder();
        for (String line : resource("confluence-items.ndjson").strip().split("\n")) {
            JsonNode item = JSON.readTree(line);
            String id = item.path("_id").asText();
            PAGE_IDS.add(id);
            ((com.fasterxml.jackson.databind.node.ObjectNode) item).remove("_id");
            for (String index : List.of("real-plugin", "real-dls")) {
                bulk.append(JSON.writeValueAsString(Map.of("index", Map.of("_index", index, "_id", id)))).append('\n')
                        .append(JSON.writeValueAsString(item)).append('\n');
            }
        }

        JsonNode callers = JSON.readTree(resource("confluence-callers.json"));
        List<String> users = new ArrayList<>();
        for (int i = 0; i < callers.size(); i++) {
            String user = "caller-" + (i + 1);
            users.add(user);
            CALLERS.put(user, callers.get(i));
            String keys = JSON.writeValueAsString(callers.get(i).path("terms"));
            bulk.append(JSON.writeValueAsString(Map.of("index", Map.of("_index", "real-dls-principals", "_id", user))))
                    .append('\n').append("{\"keys\":").append(keys).append("}\n");
        }
        node.admin("POST", "/_bulk?refresh=true", bulk.toString());

        node.admin("PUT", "/_plugins/_security/api/roles/real_reader", """
                {"cluster_permissions":["cluster_composite_ops_ro"],
                 "index_permissions":[
                   {"index_patterns":["real-plugin"],"allowed_actions":["read"]},
                   {"index_patterns":["real-dls"],"allowed_actions":["read"],"dls":%s},
                   {"index_patterns":["real-dls-principals"],"allowed_actions":["read"]}
                 ]}
                """.formatted(JSON.writeValueAsString(DLS_QUERY)));
        for (Map.Entry<String, JsonNode> caller : CALLERS.entrySet()) {
            node.admin("PUT", "/_plugins/_security/api/internalusers/" + caller.getKey(),
                    "{\"password\":\"" + PASSWORD + "\",\"backend_roles\":[]}");
            node.admin("PUT", "/_plugins/protomolt_acl/principals/" + caller.getKey(),
                    "{\"keys\":" + JSON.writeValueAsString(caller.getValue().path("terms")) + "}");
        }
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/real_reader",
                "{\"users\":" + JSON.writeValueAsString(users) + "}");
    }

    @AfterAll
    static void stopNode() {
        if (node != null) {
            node.close();
        }
    }

    private static String resource(String name) throws IOException {
        try (InputStream in = RealConfluenceAclIT.class.getResourceAsStream("/fixtures/confluence/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing fixture " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static TreeSet<String> expectedReads(JsonNode caller) {
        TreeSet<String> reads = new TreeSet<>();
        for (String id : PAGE_IDS) {
            if (caller.path("reads").path(id).asBoolean(false)) {
                reads.add(id);
            }
        }
        return reads;
    }

    private static TreeSet<String> searchIds(String user, String index) throws IOException, InterruptedException {
        OpenSearchNode.Response response = node.request(user, PASSWORD, "POST", "/" + index + "/_search", "{\"size\":100}");
        assertThat(response.status()).as(user + " " + index + ": " + response.body()).isEqualTo(200);
        TreeSet<String> ids = new TreeSet<>();
        for (JsonNode hit : response.body().path("hits").path("hits")) {
            ids.add(hit.path("_id").asText());
        }
        return ids;
    }

    @Test
    void fixtureHasBothOutcomes() {
        int allowed = 0;
        int denied = 0;
        for (JsonNode caller : CALLERS.values()) {
            for (String id : PAGE_IDS) {
                if (caller.path("reads").path(id).asBoolean(false)) {
                    allowed++;
                } else {
                    denied++;
                }
            }
        }
        assertThat(PAGE_IDS).isNotEmpty();
        assertThat(allowed).isPositive();
        assertThat(denied).isPositive();
    }

    @Test
    void pluginSearchMatchesProtomoltForEveryCaller() throws Exception {
        for (Map.Entry<String, JsonNode> caller : CALLERS.entrySet()) {
            assertThat(searchIds(caller.getKey(), "real-plugin"))
                    .as("plugin search, " + caller.getValue().path("caller").asText())
                    .isEqualTo(expectedReads(caller.getValue()));
        }
    }

    @Test
    void pluginGetMatchesProtomoltForEveryCallerAndPage() throws Exception {
        for (Map.Entry<String, JsonNode> caller : CALLERS.entrySet()) {
            for (String id : PAGE_IDS) {
                int status = node.request(caller.getKey(), PASSWORD, "GET",
                        "/real-plugin/_doc/" + java.net.URLEncoder.encode(id, StandardCharsets.UTF_8), null).status();
                boolean reads = caller.getValue().path("reads").path(id).asBoolean(false);
                assertThat(status).as(caller.getValue().path("caller").asText() + " " + id).isEqualTo(reads ? 200 : 404);
            }
        }
    }

    @Test
    void builtInDlsSearchMatchesProtomoltForEveryCaller() throws Exception {
        for (Map.Entry<String, JsonNode> caller : CALLERS.entrySet()) {
            assertThat(searchIds(caller.getKey(), "real-dls"))
                    .as("dls search, " + caller.getValue().path("caller").asText())
                    .isEqualTo(expectedReads(caller.getValue()));
        }
    }
}
