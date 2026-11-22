package ai.pipestream.opensearch.acl;

import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

import org.apache.lucene.util.SetOnce;
import org.opensearch.action.support.ActionFilter;
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
 * Registers the ACL settings and the search filter.
 */
public class AclFilterPlugin extends Plugin implements ActionPlugin {

    private final SetOnce<ClusterService> clusterService = new SetOnce<>();
    private final SetOnce<ThreadPool> threadPool = new SetOnce<>();
    private final AclFields fields;

    /**
     * Creates the plugin.
     *
     * @param settings node settings
     */
    public AclFilterPlugin(Settings settings) {
        this.fields = AclSettings.fields(settings);
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
        return List.of();
    }

    @Override
    public List<ActionFilter> getActionFilters() {
        return List.of(new AclSearchFilter(
                () -> clusterService.get().state(),
                () -> threadPool.get().getThreadContext(),
                fields));
    }
}
