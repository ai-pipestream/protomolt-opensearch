package ai.pipestream.opensearch.acl;

import java.util.List;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;

/**
 * Settings read by the ACL filter plugin.
 */
public final class AclSettings {

    /** Marks an index as ACL protected. Set when the index is created and fixed afterwards. */
    public static final Setting<Boolean> INDEX_ACL_ENABLED =
            Setting.boolSetting("index.protomolt.acl.enabled", false, Property.IndexScope, Property.Final);

    /** Keyword field holding the principal keys that grant read access. */
    public static final Setting<String> ALLOW_FIELD =
            Setting.simpleString("protomolt.acl.allow_field", "acl_allow", Property.NodeScope);

    /** Keyword field holding the principal keys that are refused access. */
    public static final Setting<String> DENY_FIELD =
            Setting.simpleString("protomolt.acl.deny_field", "acl_deny", Property.NodeScope);

    /** Nested field holding the gates, each of which must grant access. */
    public static final Setting<String> GATES_FIELD =
            Setting.simpleString("protomolt.acl.gates_field", "acl_gates", Property.NodeScope);

    /** Keyword sub-field of a gate holding the principal keys that pass the gate. */
    public static final Setting<String> GATE_ALLOW_FIELD =
            Setting.simpleString("protomolt.acl.gate_allow_field", "allow", Property.NodeScope);

    /** Boolean field that is true when the document's ACL was read completely. */
    public static final Setting<String> COMPLETE_FIELD =
            Setting.simpleString("protomolt.acl.complete_field", "acl_complete", Property.NodeScope);

    private AclSettings() {
    }

    /**
     * Returns every setting the plugin registers.
     *
     * @return the settings
     */
    public static List<Setting<?>> all() {
        return List.of(INDEX_ACL_ENABLED, ALLOW_FIELD, DENY_FIELD, GATES_FIELD, GATE_ALLOW_FIELD, COMPLETE_FIELD);
    }

    /**
     * Reads the ACL field names from node settings.
     *
     * @param settings node settings
     * @return the field names
     */
    public static AclFields fields(Settings settings) {
        return new AclFields(
                ALLOW_FIELD.get(settings),
                DENY_FIELD.get(settings),
                GATES_FIELD.get(settings),
                GATE_ALLOW_FIELD.get(settings),
                COMPLETE_FIELD.get(settings));
    }
}
