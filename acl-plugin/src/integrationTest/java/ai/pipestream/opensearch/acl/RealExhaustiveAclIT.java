package ai.pipestream.opensearch.acl;

/**
 * Runs {@link RealAclFixtureIT} on protomolt's exhaustive fixture: every subset of six identities against documents
 * with deny rules, gates, write-only rules and no rules.
 */
class RealExhaustiveAclIT extends RealAclFixtureIT {

    @Override
    String fixture() {
        return "exhaustive";
    }
}
