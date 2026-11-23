package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Loads the same documents into an index protected by the plugin and an index protected by the Security plugin's
 * document-level security (a terms lookup into a principals index), and compares what each caller can read.
 */
class DlsComparisonIT {

    private static final String PASSWORD = "Us3r-Dls-Test!pw";
    private static final List<String> USERS = List.of("alice", "bob", "carol", "dave");
    private static final Map<String, List<String>> KEYS = Map.of(
            "alice", List.of("alice", "grp:space", "grp:legal"),
            "bob", List.of("bob", "grp:space", "grp:legal"),
            "carol", List.of("carol", "grp:other"),
            "dave", List.of("dave"));
    private static final String MAPPING = """
            {
              "settings": { "index.protomolt.acl.enabled": %s, "number_of_replicas": 0 },
              "mappings": { "properties": {
                "title": { "type": "text" },
                "acl_allow": { "type": "keyword" },
                "acl_deny": { "type": "keyword" },
                "acl_complete": { "type": "boolean" },
                "acl_gates": { "type": "nested", "properties": {
                  "source": { "type": "keyword" }, "allow": { "type": "keyword" } } }
              } }
            }
            """;
    private static final String DOCS = """
            {"title":"budget space page","acl_allow":["grp:space"],"acl_complete":true}
            {"title":"budget restricted page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"source":"owner:1","allow":["alice","grp:legal"]}]}
            {"title":"budget two gate page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"source":"owner:1","allow":["grp:legal"]},{"source":"owner:2","allow":["bob"]}]}
            {"title":"budget denied page","acl_allow":["grp:space"],"acl_deny":["bob"],"acl_complete":true}
            {"title":"budget incomplete page","acl_allow":["grp:space"],"acl_complete":false}
            {"title":"budget other space page","acl_allow":["grp:other"],"acl_complete":true}
            {"title":"budget empty gate page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"source":"owner:3","allow":[]}]}
            """;
    private static final String DLS_QUERY = """
            {"bool":{
              "filter":[
                {"term":{"acl_complete":true}},
                {"terms":{"acl_allow":{"index":"dls-principals","id":"${user.name}","path":"keys"}}}
              ],
              "must_not":[
                {"terms":{"acl_deny":{"index":"dls-principals","id":"${user.name}","path":"keys"}}},
                {"nested":{"path":"acl_gates","query":{"bool":{"must_not":[
                  {"terms":{"acl_gates.allow":{"index":"dls-principals","id":"${user.name}","path":"keys"}}}
                ]}}}}
              ]
            }}
            """;
    private static final String[] IDS = {
        "space-page", "restricted-page", "two-gate-page", "denied-page", "incomplete-page", "other-page", "empty-gate-page"
    };

    private static OpenSearchNode node;

    @BeforeAll
    static void startNode() throws Exception {
        node = OpenSearchNode.start();
        node.admin("PUT", "/plugin-docs", MAPPING.formatted("true"));
        node.admin("PUT", "/dls-docs", MAPPING.formatted("false"));
        node.admin("PUT", "/dls-principals", "{\"settings\":{\"number_of_replicas\":0}}");
        StringBuilder bulk = new StringBuilder();
        String[] lines = DOCS.strip().split("\n");
        for (int i = 0; i < lines.length; i++) {
            for (String index : List.of("plugin-docs", "dls-docs")) {
                bulk.append("{\"index\":{\"_index\":\"").append(index).append("\",\"_id\":\"").append(IDS[i])
                        .append("\"}}\n").append(lines[i]).append('\n');
            }
        }
        for (String user : USERS) {
            bulk.append("{\"index\":{\"_index\":\"dls-principals\",\"_id\":\"").append(user).append("\"}}\n")
                    .append("{\"keys\":").append(json(KEYS.get(user))).append("}\n");
        }
        node.admin("POST", "/_bulk?refresh=true", bulk.toString());

        String dls = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(DLS_QUERY);
        node.admin("PUT", "/_plugins/_security/api/roles/plugin_reader", """
                {"cluster_permissions":["cluster_composite_ops_ro"],
                 "index_permissions":[{"index_patterns":["plugin-docs"],"allowed_actions":["read"]}]}
                """);
        node.admin("PUT", "/_plugins/_security/api/roles/dls_reader", """
                {"index_permissions":[
                  {"index_patterns":["dls-docs"],"allowed_actions":["read"],"dls":%s},
                  {"index_patterns":["dls-principals"],"allowed_actions":["read"]}
                ]}
                """.formatted(dls));
        for (String user : USERS) {
            node.admin("PUT", "/_plugins/_security/api/internalusers/" + user,
                    "{\"password\":\"" + PASSWORD + "\",\"backend_roles\":[]}");
            node.admin("PUT", "/_plugins/protomolt_acl/principals/" + user, "{\"keys\":" + json(KEYS.get(user)) + "}");
        }
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/plugin_reader", "{\"users\":" + json(USERS) + "}");
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/dls_reader", "{\"users\":" + json(USERS) + "}");
    }

    @AfterAll
    static void stopNode() {
        if (node != null) {
            node.close();
        }
    }

    private static String json(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            out.append(i == 0 ? "" : ",").append('"').append(values.get(i)).append('"');
        }
        return out.append(']').toString();
    }

    private static OpenSearchNode.Response as(String user, String method, String path, String body)
            throws IOException, InterruptedException {
        return node.request(user, PASSWORD, method, path, body);
    }

    private static List<String> searchIds(String user, String index) throws IOException, InterruptedException {
        OpenSearchNode.Response response = as(user, "POST", "/" + index + "/_search", "{\"size\":50}");
        assertThat(response.status()).as(user + " " + index + ": " + response.body()).isEqualTo(200);
        List<String> ids = new ArrayList<>();
        for (JsonNode hit : response.body().path("hits").path("hits")) {
            ids.add(hit.path("_id").asText());
        }
        return ids;
    }

    @Test
    void searchResultsMatchForEveryCaller() throws Exception {
        Map<String, List<String>> expected = Map.of(
                "alice", List.of("space-page", "restricted-page", "denied-page"),
                "bob", List.of("space-page", "restricted-page", "two-gate-page"),
                "carol", List.of("other-page"),
                "dave", List.of());
        for (String user : USERS) {
            assertThat(searchIds(user, "plugin-docs")).as("plugin, " + user)
                    .containsExactlyInAnyOrderElementsOf(expected.get(user));
            assertThat(searchIds(user, "dls-docs")).as("dls, " + user)
                    .containsExactlyInAnyOrderElementsOf(expected.get(user));
        }
    }

    @Test
    void getByIdMatchesForEveryCallerAndDocument() throws Exception {
        for (String user : USERS) {
            for (String id : IDS) {
                int plugin = as(user, "GET", "/plugin-docs/_doc/" + id, null).status();
                int dls = as(user, "GET", "/dls-docs/_doc/" + id, null).status();
                assertThat(dls).as(user + " " + id).isEqualTo(plugin);
            }
        }
    }

    @Test
    void dlsCallersCanReadEveryonesPrincipals() throws Exception {
        OpenSearchNode.Response dls = as("carol", "GET", "/dls-principals/_doc/alice", null);
        assertThat(dls.status()).isEqualTo(200);
        assertThat(dls.body().path("_source").path("keys").toString()).contains("grp:legal");

        OpenSearchNode.Response plugin = as("carol", "GET", "/.protomolt-acl-principals/_doc/alice", null);
        assertThat(plugin.body().toString()).doesNotContain("grp:legal");
    }

    @Test
    void globalAggregationFailsUnderDlsAndIsRejectedByThePlugin() throws Exception {
        String body = "{\"size\":0,\"aggs\":{\"all\":{\"global\":{}}}}";
        OpenSearchNode.Response dls = as("dave", "POST", "/dls-docs/_search", body);
        OpenSearchNode.Response plugin = as("dave", "POST", "/plugin-docs/_search", body);
        assertThat(plugin.status()).isEqualTo(400);
        assertThat(dls.status()).as(dls.body().toString()).isEqualTo(500);
        assertThat(dls.body().toString()).doesNotContain("doc_count");
    }

    @Test
    void termSuggestLeaksHiddenTermsUnderDlsAndIsRejectedByThePlugin() throws Exception {
        String body = "{\"suggest\":{\"s\":{\"text\":\"budgt\",\"term\":{\"field\":\"title\"}}}}";
        OpenSearchNode.Response dls = as("dave", "POST", "/dls-docs/_search", body);
        OpenSearchNode.Response plugin = as("dave", "POST", "/plugin-docs/_search", body);
        assertThat(plugin.status()).isEqualTo(400);
        assertThat(dls.status()).isEqualTo(200);
        assertThat(searchIds("dave", "dls-docs")).isEmpty();
        JsonNode option = dls.body().path("suggest").path("s").get(0).path("options").get(0);
        assertThat(option.path("text").asText()).isEqualTo("budget");
        assertThat(option.path("freq").asInt()).isEqualTo(7);
    }
}
