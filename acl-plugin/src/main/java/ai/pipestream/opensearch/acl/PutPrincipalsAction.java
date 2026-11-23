package ai.pipestream.opensearch.acl;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;

/**
 * Replaces the principal keys stored for one caller.
 */
public final class PutPrincipalsAction extends ActionType<AcknowledgedResponse> {

    /** Action name; a cluster permission. */
    public static final String NAME = "cluster:admin/protomolt/acl/principals/put";

    /** The action. */
    public static final PutPrincipalsAction INSTANCE = new PutPrincipalsAction();

    private PutPrincipalsAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
