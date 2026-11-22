package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

class AclFilterPluginIT {

    private static final String PASSWORD = "Us3r-Acl-Test!pw";
    private static final String MAPPING = """
            {
              "settings": { "index.protomolt.acl.enabled": %s, "number_of_replicas": 0 },
              "mappings": { "properties": {
                "title": { "type": "text" },
                "acl_allow": { "type": "keyword" },
                "acl_complete": { "type": "boolean" },
                "acl_gates": { "type": "nested", "properties": { "allow": { "type": "keyword" } } }
              } }
            }
            """;

    private static OpenSearchNode node;

    @BeforeAll
    static void startNode() throws Exception {
        node = OpenSearchNode.start();

        node.admin("PUT", "/acl-docs", MAPPING.formatted("true"));
        node.admin("PUT", "/open-docs", MAPPING.formatted("false"));
        node.admin("POST", "/_bulk?refresh=true", """
                {"index":{"_index":"acl-docs","_id":"space-page"}}
                {"title":"budget space page","acl_allow":["grp:space"],"acl_complete":true}
                {"index":{"_index":"acl-docs","_id":"restricted-page"}}
                {"title":"budget restricted page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"allow":["alice","grp:legal"]}]}
                {"index":{"_index":"acl-docs","_id":"two-gate-page"}}
                {"title":"budget two gate page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"allow":["grp:legal"]},{"allow":["bob"]}]}
                {"index":{"_index":"acl-docs","_id":"incomplete-page"}}
                {"title":"budget incomplete page","acl_allow":["grp:space"],"acl_complete":false}
                {"index":{"_index":"acl-docs","_id":"other-space-page"}}
                {"title":"budget other space page","acl_allow":["grp:other"],"acl_complete":true}
                {"index":{"_index":"open-docs","_id":"open-page"}}
                {"title":"budget open page"}
                """);

        node.admin("PUT", "/_plugins/_security/api/roles/acl_reader", """
                {"cluster_permissions":["cluster_composite_ops_ro"],
                 "index_permissions":[{"index_patterns":["acl-docs","open-docs"],"allowed_actions":["read"]}]}
                """);
        createUser("alice", "\"grp:space\",\"grp:legal\"");
        createUser("bob", "\"grp:space\",\"grp:legal\"");
        createUser("carol", "\"grp:other\"");
        createUser("dave", "");
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/acl_reader", """
                {"users":["alice","bob","carol","dave"]}
                """);
    }

    @AfterAll
    static void stopNode() {
        if (node != null) {
            node.close();
        }
    }

    private static void createUser(String name, String backendRoles) throws IOException, InterruptedException {
        node.admin("PUT", "/_plugins/_security/api/internalusers/" + name,
                "{\"password\":\"" + PASSWORD + "\",\"backend_roles\":[" + backendRoles + "]}");
    }

    private static List<String> searchIds(String user, String path, String body)
            throws IOException, InterruptedException {
        OpenSearchNode.Response response = node.request(user, PASSWORD, "POST", path, body);
        assertThat(response.status()).as(response.body().toString()).isEqualTo(200);
        return ids(response.body());
    }

    private static List<String> ids(JsonNode searchResponse) {
        List<String> ids = new ArrayList<>();
        for (JsonNode hit : searchResponse.path("hits").path("hits")) {
            ids.add(hit.path("_id").asText());
        }
        return ids;
    }

    @Test
    void bothPluginsAreLoaded() throws Exception {
        JsonNode plugins = node.admin("GET", "/_nodes/plugins", null);
        List<String> names = new ArrayList<>();
        for (JsonNode n : plugins.path("nodes")) {
            for (JsonNode p : n.path("plugins")) {
                names.add(p.path("name").asText());
            }
        }
        assertThat(names).contains("opensearch-security", "protomolt-acl");
    }

    @Test
    void userInOneGateSeesSpaceAndRestrictedPage() throws Exception {
        assertThat(searchIds("alice", "/acl-docs/_search", "{\"size\":50}"))
                .containsExactlyInAnyOrder("space-page", "restricted-page");
    }

    @Test
    void userPassingEveryGateSeesTwoGatePage() throws Exception {
        assertThat(searchIds("bob", "/acl-docs/_search", "{\"size\":50}"))
                .containsExactlyInAnyOrder("space-page", "restricted-page", "two-gate-page");
    }

    @Test
    void userOfOtherSpaceSeesOnlyThatSpace() throws Exception {
        assertThat(searchIds("carol", "/acl-docs/_search", "{\"size\":50}")).containsExactly("other-space-page");
    }

    @Test
    void userWithoutGroupsSeesNothing() throws Exception {
        assertThat(searchIds("dave", "/acl-docs/_search", "{\"size\":50}")).isEmpty();
    }

    @Test
    void adminRoleDoesNotBypassTheAcl() throws Exception {
        OpenSearchNode.Response response = node.request(
                OpenSearchNode.ADMIN, OpenSearchNode.ADMIN_PASSWORD, "POST", "/acl-docs/_search", "{\"size\":50}");
        assertThat(ids(response.body())).isEmpty();
    }

    @Test
    void callerQueryIsKeptAndFiltered() throws Exception {
        assertThat(searchIds("alice", "/acl-docs/_search",
                "{\"query\":{\"match\":{\"title\":\"restricted\"}}}"))
                .containsExactly("restricted-page");
        assertThat(searchIds("carol", "/acl-docs/_search",
                "{\"query\":{\"match\":{\"title\":\"restricted\"}}}"))
                .isEmpty();
    }

    @Test
    void unprotectedIndexInSameSearchIsUnfiltered() throws Exception {
        assertThat(searchIds("dave", "/acl-docs,open-docs/_search", "{\"size\":50}")).containsExactly("open-page");
        assertThat(searchIds("carol", "/*-docs/_search", "{\"size\":50}"))
                .containsExactlyInAnyOrder("open-page", "other-space-page");
    }

    @Test
    void countIsFiltered() throws Exception {
        OpenSearchNode.Response response = node.request("alice", PASSWORD, "POST", "/acl-docs/_count", "{}");
        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body().path("count").asInt()).isEqualTo(2);
    }

    @Test
    void multiSearchIsFiltered() throws Exception {
        OpenSearchNode.Response response = node.request("carol", PASSWORD, "POST", "/_msearch", """
                {"index":"acl-docs"}
                {"size":50}
                """);
        assertThat(response.status()).isEqualTo(200);
        assertThat(ids(response.body().path("responses").get(0))).containsExactly("other-space-page");
    }

    @Test
    void aggregationsOnlyCountVisibleDocuments() throws Exception {
        OpenSearchNode.Response response = node.request("alice", PASSWORD, "POST", "/acl-docs/_search", """
                {"size":0,"aggs":{"allow":{"terms":{"field":"acl_allow"}}}}
                """);
        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body().path("hits").path("total").path("value").asInt()).isEqualTo(2);
        JsonNode bucket = response.body().path("aggregations").path("allow").path("buckets").get(0);
        assertThat(bucket.path("key").asText()).isEqualTo("grp:space");
        assertThat(bucket.path("doc_count").asInt()).isEqualTo(2);
    }

    @Test
    void globalAggregationIsRejected() throws Exception {
        OpenSearchNode.Response response = node.request("alice", PASSWORD, "POST", "/acl-docs/_search", """
                {"size":0,"aggs":{"all":{"global":{}}}}
                """);
        assertThat(response.status()).isEqualTo(400);
    }

    @Test
    void suggestIsRejected() throws Exception {
        OpenSearchNode.Response response = node.request("alice", PASSWORD, "POST", "/acl-docs/_search", """
                {"suggest":{"s":{"text":"budgt","term":{"field":"title"}}}}
                """);
        assertThat(response.status()).isEqualTo(400);
    }

    @Test
    void protectionCannotBeSwitchedOff() throws Exception {
        OpenSearchNode.Response response = node.request(OpenSearchNode.ADMIN, OpenSearchNode.ADMIN_PASSWORD,
                "PUT", "/acl-docs/_settings", "{\"index.protomolt.acl.enabled\":false}");
        assertThat(response.status()).isEqualTo(400);
    }
}
