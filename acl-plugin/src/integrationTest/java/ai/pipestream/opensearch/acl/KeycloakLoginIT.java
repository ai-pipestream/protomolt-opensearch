package ai.pipestream.opensearch.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Logs in through Keycloak, sends the access token to OpenSearch and checks that the ACL filter uses the user and
 * groups from the token.
 */
class KeycloakLoginIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
    private static final String KEYCLOAK_ALIAS = "keycloak";

    private static Network network;
    private static GenericContainer<?> keycloak;
    private static OpenSearchNode node;

    @BeforeAll
    static void start() throws Exception {
        network = Network.newNetwork();
        keycloak = new GenericContainer<>(System.getProperty("protomolt.test.keycloak.image", "quay.io/keycloak/keycloak:26.8.2"))
                .withNetwork(network)
                .withNetworkAliases(KEYCLOAK_ALIAS)
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "Kc-Admin-Test!1")
                .withCopyFileToContainer(MountableFile.forClasspathResource("keycloak/protomolt-realm.json"),
                        "/opt/keycloak/data/import/protomolt-realm.json")
                .withCommand("start-dev", "--import-realm")
                .withExposedPorts(8080)
                .waitingFor(Wait.forHttp("/realms/protomolt/.well-known/openid-configuration")
                        .forPort(8080)
                        .withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();

        node = OpenSearchNode.start(network,
                Map.of("plugins.security.unsupported.restapi.allow_securityconfig_modification", "true"));
        addOpenIdDomain();

        node.admin("PUT", "/acl-docs", """
                {
                  "settings": { "index.protomolt.acl.enabled": true, "number_of_replicas": 0 },
                  "mappings": { "properties": {
                    "title": { "type": "text" },
                    "acl_allow": { "type": "keyword" },
                    "acl_complete": { "type": "boolean" },
                    "acl_gates": { "type": "nested", "properties": { "allow": { "type": "keyword" } } }
                  } }
                }
                """);
        node.admin("POST", "/_bulk?refresh=true", """
                {"index":{"_index":"acl-docs","_id":"space-page"}}
                {"title":"space page","acl_allow":["grp:space"],"acl_complete":true}
                {"index":{"_index":"acl-docs","_id":"legal-page"}}
                {"title":"legal page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"allow":["grp:legal"]}]}
                {"index":{"_index":"acl-docs","_id":"erin-only-page"}}
                {"title":"erin only page","acl_allow":["grp:space"],"acl_complete":true,"acl_gates":[{"allow":["erin"]}]}
                {"index":{"_index":"acl-docs","_id":"other-page"}}
                {"title":"other page","acl_allow":["grp:other"],"acl_complete":true}
                """);
        node.admin("PUT", "/_plugins/_security/api/roles/acl_reader", """
                {"cluster_permissions":["cluster_composite_ops_ro"],
                 "index_permissions":[{"index_patterns":["acl-docs"],"allowed_actions":["read"]}]}
                """);
        node.admin("PUT", "/_plugins/_security/api/rolesmapping/acl_reader", """
                {"users":["erin","frank","gina"]}
                """);
    }

    private static void addOpenIdDomain() throws IOException, InterruptedException {
        JsonNode current = node.admin("GET", "/_plugins/_security/api/securityconfig", null);
        ObjectNode dynamic = (ObjectNode) current.path("config").path("dynamic");
        ObjectNode authc = (ObjectNode) dynamic.path("authc");
        ObjectNode domain = authc.putObject("openid_auth_domain");
        domain.put("http_enabled", true);
        domain.put("transport_enabled", false);
        domain.put("order", 0);
        ObjectNode authenticator = domain.putObject("http_authenticator");
        authenticator.put("type", "openid");
        authenticator.put("challenge", false);
        ObjectNode config = authenticator.putObject("config");
        config.put("subject_key", "preferred_username");
        config.put("roles_key", "groups");
        config.put("openid_connect_url",
                "http://" + KEYCLOAK_ALIAS + ":8080/realms/protomolt/.well-known/openid-configuration");
        domain.putObject("authentication_backend").put("type", "noop");
        ObjectNode body = JSON.createObjectNode();
        body.set("dynamic", dynamic);
        node.admin("PUT", "/_plugins/_security/api/securityconfig/config", JSON.writeValueAsString(body));
    }

    @AfterAll
    static void stop() {
        if (node != null) {
            node.close();
        }
        if (keycloak != null) {
            keycloak.stop();
        }
        if (network != null) {
            network.close();
        }
    }

    private static String login(String user, String password) throws IOException, InterruptedException {
        String form = "grant_type=password&client_id=opensearch&scope=openid"
                + "&username=" + URLEncoder.encode(user, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);
        URI token = URI.create("http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080)
                + "/realms/protomolt/protocol/openid-connect/token");
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(token)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body()).path("access_token").asText();
    }

    private static List<String> searchIds(String token) throws IOException, InterruptedException {
        OpenSearchNode.Response response = node.requestWithToken(token, "POST", "/acl-docs/_search", "{\"size\":50}");
        assertThat(response.status()).as(response.body().toString()).isEqualTo(200);
        List<String> ids = new ArrayList<>();
        for (JsonNode hit : response.body().path("hits").path("hits")) {
            ids.add(hit.path("_id").asText());
        }
        return ids;
    }

    @Test
    void tokenCarriesUserAndGroupsIntoOpenSearch() throws Exception {
        OpenSearchNode.Response who = node.requestWithToken(login("erin", "Erin-Kc-Test!1"),
                "GET", "/_plugins/_security/authinfo", null);
        assertThat(who.status()).isEqualTo(200);
        assertThat(who.body().path("user_name").asText()).isEqualTo("erin");
        List<String> backendRoles = new ArrayList<>();
        ((ArrayNode) who.body().path("backend_roles")).forEach(role -> backendRoles.add(role.asText()));
        assertThat(backendRoles).containsExactlyInAnyOrder("grp:space", "grp:legal");
    }

    @Test
    void keycloakUserSeesDocumentsAllowedByTokenGroups() throws Exception {
        assertThat(searchIds(login("erin", "Erin-Kc-Test!1")))
                .containsExactlyInAnyOrder("space-page", "legal-page", "erin-only-page");
        assertThat(searchIds(login("frank", "Frank-Kc-Test!1"))).containsExactly("other-page");
    }

    @Test
    void keycloakUserCannotGetHiddenDocument() throws Exception {
        OpenSearchNode.Response response = node.requestWithToken(login("frank", "Frank-Kc-Test!1"),
                "GET", "/acl-docs/_doc/legal-page", null);
        assertThat(response.status()).isEqualTo(404);
    }

    @Test
    void invalidTokenIsRefused() throws Exception {
        OpenSearchNode.Response response = node.requestWithToken("not-a-token", "POST", "/acl-docs/_search", "{}");
        assertThat(response.status()).isEqualTo(401);
    }

    @Test
    void storedPrincipalsAddGroupsTheTokenDoesNotCarry() throws Exception {
        String token = login("gina", "Gina-Kc-Test!1");
        assertThat(searchIds(token)).isEmpty();

        node.admin("PUT", "/_plugins/protomolt_acl/principals/gina", "{\"keys\":[\"grp:space\",\"grp:legal\"]}");

        assertThat(searchIds(token)).containsExactlyInAnyOrder("space-page", "legal-page");
    }
}
