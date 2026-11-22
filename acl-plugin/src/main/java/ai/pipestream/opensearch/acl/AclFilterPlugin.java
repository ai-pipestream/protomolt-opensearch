package ai.pipestream.opensearch.acl;

import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

import org.apache.lucene.util.SetOnce;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.identity.PluginSubject;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.IdentityAwarePlugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * Registers the ACL settings, the search and document read filters, and the principal store with its system index
 * and put action.
 */
public class AclFilterPlugin extends Plugin implements ActionPlugin, SystemIndexPlugin, IdentityAwarePlugin {

    private final SetOnce<ClusterService> clusterService = new SetOnce<>();
    private final SetOnce<ThreadPool> threadPool = new SetOnce<>();
    private final SetOnce<Client> client = new SetOnce<>();
    private final AclFields fields;
    private final PrincipalStore store;
    private final CallerPrincipalResolver principals;

    /**
     * Creates the plugin.
     *
     * @param settings node settings
     */
    public AclFilterPlugin(Settings settings) {
        this.fields = AclSettings.fields(settings);
        this.store = new PrincipalStore(client::get, () -> threadPool.get().getThreadContext());
        this.principals = new CallerPrincipalResolver(() -> threadPool.get().getThreadContext(), store);
    }

    @Override
    public void assignSubject(PluginSubject pluginSubject) {
        store.assignSubject(pluginSubject);
    }

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        return List.of(new SystemIndexDescriptor(PrincipalStore.INDEX, "Principal keys of callers for ACL filtering"));
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(new ActionHandler<>(PutPrincipalsAction.INSTANCE, TransportPutPrincipalsAction.class));
    }

    @Override
    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
        return List.of(new RestPutPrincipalsAction());
    }

    @Override
    public List<Setting<?>> getSettings() {
        return AclSettings.all();
    }

    @Override
    public Collection<Object> createComponents(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService,
            ScriptService scriptService,
            NamedXContentRegistry xContentRegistry,
            Environment environment,
            NodeEnvironment nodeEnvironment,
            NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
        this.clusterService.set(clusterService);
        this.threadPool.set(threadPool);
        this.client.set(client);
        return List.of(store);
    }

    @Override
    public List<ActionFilter> getActionFilters() {
        return List.of(
                new AclSearchFilter(
                        () -> clusterService.get().state(),
                        principals,
                        fields),
                new AclDocumentReadFilter(
                        () -> clusterService.get().state(),
                        () -> threadPool.get().getThreadContext(),
                        client::get,
                        principals,
                        fields));
    }
}
