package ai.pipestream.opensearch.acl;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Stores a caller's principal keys in the {@link PrincipalStore}.
 */
public final class TransportPutPrincipalsAction extends HandledTransportAction<PutPrincipalsRequest, AcknowledgedResponse> {

    private final PrincipalStore store;

    /**
     * Creates the action.
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param store the principal store
     */
    @Inject
    public TransportPutPrincipalsAction(TransportService transportService, ActionFilters actionFilters, PrincipalStore store) {
        super(PutPrincipalsAction.NAME, transportService, actionFilters, PutPrincipalsRequest::new);
        this.store = store;
    }

    @Override
    protected void doExecute(Task task, PutPrincipalsRequest request, ActionListener<AcknowledgedResponse> listener) {
        store.put(request.user(), request.keys(), ActionListener.wrap(
                ignored -> listener.onResponse(new AcknowledgedResponse(true)),
                listener::onFailure));
    }
}
