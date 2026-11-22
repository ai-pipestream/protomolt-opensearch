package ai.pipestream.opensearch.acl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

/**
 * {@code PUT /_plugins/protomolt_acl/principals/{user}} with body {@code {"keys": [...]}}.
 */
public final class RestPutPrincipalsAction extends BaseRestHandler {

    /** Creates the handler. */
    public RestPutPrincipalsAction() {
    }

    @Override
    public String getName() {
        return "protomolt_acl_put_principals";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.PUT, "/_plugins/protomolt_acl/principals/{user}"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String user = request.param("user");
        List<String> keys = new ArrayList<>();
        try (XContentParser parser = request.contentParser()) {
            Map<String, Object> body = parser.map();
            if (body.get(PrincipalStore.KEYS_FIELD) instanceof List<?> values) {
                for (Object value : values) {
                    if (!(value instanceof String key)) {
                        throw new IllegalArgumentException("keys must be strings");
                    }
                    keys.add(key);
                }
            } else {
                throw new IllegalArgumentException("body must hold a keys array");
            }
        }
        PutPrincipalsRequest put = new PutPrincipalsRequest(user, keys);
        return channel -> client.execute(PutPrincipalsAction.INSTANCE, put, new RestToXContentListener<>(channel));
    }
}
