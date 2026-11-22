package ai.pipestream.opensearch.acl;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request to replace the principal keys stored for one caller.
 */
public final class PutPrincipalsRequest extends ActionRequest {

    private final String user;
    private final List<String> keys;

    /**
     * Creates the request.
     *
     * @param user the Security plugin user name
     * @param keys the caller's keys
     */
    public PutPrincipalsRequest(String user, List<String> keys) {
        this.user = user;
        this.keys = List.copyOf(keys);
    }

    /**
     * Reads the request from a stream.
     *
     * @param in the stream
     * @throws IOException when the stream cannot be read
     */
    public PutPrincipalsRequest(StreamInput in) throws IOException {
        super(in);
        this.user = in.readString();
        this.keys = in.readStringList();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(user);
        out.writeStringCollection(keys);
    }

    @Override
    public ActionRequestValidationException validate() {
        if (user == null || user.isBlank()) {
            ActionRequestValidationException e = new ActionRequestValidationException();
            e.addValidationError("user is required");
            return e;
        }
        return null;
    }

    /**
     * Returns the Security plugin user name.
     *
     * @return the user name
     */
    public String user() {
        return user;
    }

    /**
     * Returns the caller's keys.
     *
     * @return the keys
     */
    public List<String> keys() {
        return keys;
    }
}
