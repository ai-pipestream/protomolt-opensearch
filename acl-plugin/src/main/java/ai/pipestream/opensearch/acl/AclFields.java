package ai.pipestream.opensearch.acl;

/**
 * Names of the document fields the ACL filter reads.
 *
 * @param allow keyword field with the principal keys that grant read access
 * @param deny keyword field with the principal keys that are refused access
 * @param gates nested field with the gates
 * @param gateAllow keyword sub-field of a gate with the principal keys that pass it
 * @param complete boolean field that is true when the ACL was read completely
 */
public record AclFields(String allow, String deny, String gates, String gateAllow, String complete) {

    /**
     * Returns the full path of the gate allow field.
     *
     * @return the gate allow field path
     */
    public String gateAllowPath() {
        return gates + "." + gateAllow;
    }
}
