package ai.pipestream.opensearch.acl;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.opensearch.testcontainers.OpenSearchContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A single OpenSearch node in a container with the Security plugin on and the ACL plugin installed.
 */
final class OpenSearchNode implements AutoCloseable {

    static final String ADMIN = "admin";
    static final String ADMIN_PASSWORD = "Pr0tomolt-Acl-Test!";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final OpenSearchContainer<?> container;
    private final HttpClient http;

    private OpenSearchNode(OpenSearchContainer<?> container, HttpClient http) {
        this.container = container;
        this.http = http;
    }

    /**
     * Builds the image with the plugin zip installed and starts the node.
     */
    static OpenSearchNode start() throws GeneralSecurityException {
        return start(null, Map.of());
    }

    /**
     * Builds the image with the plugin zip installed and starts the node on the given network with extra
     * environment variables.
     */
    static OpenSearchNode start(Network network, Map<String, String> env) throws GeneralSecurityException {
        String baseImage = System.getProperty("protomolt.test.opensearch.image", "opensearchproject/opensearch:3.10.0");
        Path zip = Path.of(System.getProperty("protomolt.acl.plugin.zip"));
        if (!Files.isRegularFile(zip)) {
            throw new IllegalStateException("plugin zip not found: " + zip);
        }
        String version = DockerImageName.parse(baseImage).getVersionPart();
        String image = new ImageFromDockerfile("protomolt-acl-opensearch:" + version, true)
                .withFileFromPath("protomolt-acl.zip", zip)
                .withDockerfileFromBuilder(builder -> builder
                        .from(baseImage)
                        .copy("protomolt-acl.zip", "/tmp/protomolt-acl.zip")
                        .run("/usr/share/opensearch/bin/opensearch-plugin install --batch file:///tmp/protomolt-acl.zip")
                        .build())
                .get();
        OpenSearchContainer<?> container = new OpenSearchContainer<>(
                DockerImageName.parse(image).asCompatibleSubstituteFor("opensearchproject/opensearch"))
                .withSecurityEnabled()
                .withEnv("OPENSEARCH_INITIAL_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withEnv(env);
        if (network != null) {
            container.withNetwork(network);
        }
        container.start();
        OpenSearchNode node = new OpenSearchNode(container, insecureClient());
        node.awaitSecurityReady();
        return node;
    }

    /** Status code and parsed JSON body of a response. */
    record Response(int status, JsonNode body) {
    }

    Response request(String user, String password, String method, String path, String body)
            throws IOException, InterruptedException {
        HttpResponse<String> response = send(user, password, method, path, body);
        return new Response(response.statusCode(), parse(response.body()));
    }

    private static JsonNode parse(String body) {
        String trimmed = body.strip();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                return JSON.readTree(trimmed);
            } catch (IOException e) {
                throw new IllegalStateException("unreadable JSON response: " + body, e);
            }
        }
        return JSON.createObjectNode().put("text", body);
    }

    JsonNode admin(String method, String path, String body) throws IOException, InterruptedException {
        Response response = request(ADMIN, ADMIN_PASSWORD, method, path, body);
        if (response.status() >= 300) {
            throw new IllegalStateException(method + " " + path + " answered " + response.status() + ": " + response.body());
        }
        return response.body();
    }

    Response requestWithToken(String accessToken, String method, String path, String body)
            throws IOException, InterruptedException {
        HttpResponse<String> response = sendWithAuthorization("Bearer " + accessToken, method, path, body);
        return new Response(response.statusCode(), parse(response.body()));
    }

    private HttpResponse<String> send(String user, String password, String method, String path, String body)
            throws IOException, InterruptedException {
        String credentials = Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
        return sendWithAuthorization("Basic " + credentials, method, path, body);
    }

    private HttpResponse<String> sendWithAuthorization(String authorization, String method, String path, String body)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(container.getHttpHostAddress() + path))
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", authorization)
                .header("Content-Type", path.contains("_bulk") || path.contains("_msearch")
                        ? "application/x-ndjson" : "application/json");
        builder.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private void awaitSecurityReady() {
        long deadline = System.nanoTime() + Duration.ofMinutes(3).toNanos();
        while (System.nanoTime() < deadline) {
            try {
                if (send(ADMIN, ADMIN_PASSWORD, "GET", "/_plugins/_security/health", null).statusCode() == 200
                        && send(ADMIN, ADMIN_PASSWORD, "GET", "/_cluster/health?wait_for_status=yellow&timeout=5s", null)
                                .statusCode() == 200) {
                    return;
                }
            } catch (IOException e) {
                // node not answering yet
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            sleep();
        }
        throw new IllegalStateException("security plugin did not become ready: " + container.getLogs());
    }

    private static void sleep() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static HttpClient insecureClient() throws GeneralSecurityException {
        TrustManager trustAll = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, new TrustManager[] {trustAll}, null);
        return HttpClient.newBuilder()
                .sslContext(ssl)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Override
    public void close() {
        container.stop();
    }
}
