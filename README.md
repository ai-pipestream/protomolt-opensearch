# protomolt-opensearch

OpenSearch plugins for protomolt.

## acl-plugin

`protomolt-acl` limits search results on ACL protected indices to the documents the caller may read. It runs next
to the built-in OpenSearch Security plugin: Security authenticates the caller (internal users, or OpenID Connect from Keycloak
or Entra), and this plugin reads the caller's user name and backend roles from
the request and adds an access filter to the query.

Built for OpenSearch 3.10.0 only. A plugin zip installs on exactly the OpenSearch version it was built against.

### Index setup

An index is protected when it is created with `index.protomolt.acl.enabled: true`. The setting cannot be changed
afterwards. Documents carry:

| Field | Type | Meaning |
|---|---|---|
| `acl_allow` | keyword | Principal keys that grant read access. One match is enough. |
| `acl_deny` | keyword | Principal keys that are refused. Any match hides the document. |
| `acl_gates` | nested, with keyword `allow` | Each gate must hold at least one of the caller's principal keys. |
| `acl_complete` | boolean | Must be `true`. A document whose ACL could not be read completely is never returned. |

Field names can be changed with the node settings `protomolt.acl.allow_field`, `protomolt.acl.deny_field`, `protomolt.acl.gates_field`,
`protomolt.acl.gate_allow_field` and `protomolt.acl.complete_field`.

The caller's principal keys are the user name and each backend role the Security plugin reports, plus the keys stored
for that user name in the plugin's principal store. All keys are lower-cased before matching, so index the ACL values
lower-cased. A caller with no authenticated user matches nothing.

### Principal store

Keys a caller holds beyond its login (expanded groups, linked accounts, access classes) are kept in the system index
`.protomolt-acl-principals`, one document per Security plugin user name. Only the plugin reads it; callers cannot.
Replace a user's keys with:

```
PUT /_plugins/protomolt_acl/principals/{user}
{"keys": ["atlassian-account:...", "atlassian-group:...", "public:public"]}
```

This needs the cluster permission `cluster:admin/protomolt/acl/principals/put`. Each protected read does one realtime
get on the store.

### Searches

- `_search`, `_count` and `_msearch` on a protected index get the access filter. Unprotected indices in the same
  request are not filtered.
- When the plugin cannot tell which indices a search reaches (for example cross-cluster searches), every index in it
  is filtered.
- `suggest` and `global` aggregations are rejected on protected indices.
- get, mget, explain and term vectors return a document the caller may not read as not found. The ACL fields are
  read with an internal realtime multi get, so source filtering on the request does not skip the check.
- Term statistics, artificial documents and multi term vectors are rejected on protected indices.
- Scores and explanations still use index-wide term statistics, which include documents the caller cannot see.

### Build and test

```
./gradlew build
```

Builds the plugin zip into `acl-plugin/build/distributions/`, runs the unit tests and the container tests:

- `AclFilterPluginIT` installs the zip into an `opensearchproject/opensearch:3.10.0` container with the Security
  plugin on and reads as several internal users.
- `KeycloakLoginIT` adds an OpenID Connect auth domain backed by a Keycloak container
  (`quay.io/keycloak/keycloak:26.8.2`), logs users in through Keycloak and checks that the user name and `groups`
  claim from the access token drive the filter, and that stored keys add groups the token does not carry.
- `RealConfluenceAclIT` and `RealSharePointAclIT` index protomolt's document security for real Confluence pages and
  SharePoint drives, lists and items (fixtures in `src/integrationTest/resources/fixtures/`) and check that the plugin's search and get, and the Security
  plugin's document-level security, give exactly protomolt's own read decision for every caller and item.
- `DlsComparisonIT` runs the same documents through the plugin and through built-in document-level security (a terms
  lookup into a principals index) and records where they differ. Docker is required. Any compiler, javadoc or Gradle deprecation
warning fails the build.

Install on a node:

```
bin/opensearch-plugin install file:///path/to/protomolt-acl-<version>-os3.10.0.zip
```
