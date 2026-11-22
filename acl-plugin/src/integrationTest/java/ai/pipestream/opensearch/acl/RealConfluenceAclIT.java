package ai.pipestream.opensearch.acl;

/**
 * Runs {@link RealAclFixtureIT} on Confluence pages recorded live on the CLAUDEGRPC test space.
 */
class RealConfluenceAclIT extends RealAclFixtureIT {

    @Override
    String fixture() {
        return "confluence";
    }
}
