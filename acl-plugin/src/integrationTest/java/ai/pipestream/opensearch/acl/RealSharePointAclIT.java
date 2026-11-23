package ai.pipestream.opensearch.acl;

/**
 * Runs {@link RealAclFixtureIT} on SharePoint drives, lists and items recorded live on the WelcomeToPipestream test site.
 */
class RealSharePointAclIT extends RealAclFixtureIT {

    @Override
    String fixture() {
        return "sharepoint";
    }
}
