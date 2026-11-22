# protomolt-opensearch

OpenSearch plugins for protomolt.

## acl-plugin

`protomolt-acl` limits search results on ACL protected indices to the documents the caller may read. It runs next
to the built-in OpenSearch Security plugin: Security authenticates the caller (internal users today; JWT or OpenID
Connect, for example Keycloak or Entra, later), and this plugin reads the caller's user name and backend roles from
the request and adds an access filter to the query.

Built for OpenSearch 3.10.0 only. A plugin zip installs on exactly the OpenSearch version it was built against.

### Index setup

An index is protected when it is created with `index.protomolt.acl.enabled: true`. The setting cannot be changed
afterwards. Documents carry:

| Field | Type | Meaning |
|---|---|---|
| `acl_allow` | keyword | Principal keys that grant read access. One match is enough. |
| `acl_gates` | nested, with keyword `allow` | Each gate must hold at least one of the caller's principal keys. |
| `acl_complete` | boolean | Must be `true`. A document whose ACL could not be read completely is never returned. |

Field names can be changed with the node settings `protomolt.acl.allow_field`, `protomolt.acl.gates_field`,
`protomolt.acl.gate_allow_field` and `protomolt.acl.complete_field`.

The caller's principal keys are the user name and each backend role, exactly as the Security plugin reports them. A
caller with no authenticated user matches nothing.

### Searches

- `_search`, `_count` and `_msearch` on a protected index get the access filter. Unprotected indices in the same
  request are not filtered.
- When the plugin cannot tell which indices a search reaches (for example cross-cluster searches), every index in it
  is filtered.
- `suggest` and `global` aggregations are rejected on protected indices.
- Not filtered yet: get, mget, explain, term vectors and other non-search reads.

### Build and test

```
./gradlew build
```

Builds the plugin zip into `acl-plugin/build/distributions/`, runs the unit tests and runs
`AclFilterPluginIT`, which installs the zip into an `opensearchproject/opensearch:3.10.0` container with the Security
plugin on and searches as several internal users. Docker is required. Any compiler, javadoc or Gradle deprecation
warning fails the build.

Install on a node:

```
bin/opensearch-plugin install file:///path/to/protomolt-acl-<version>-os3.10.0.zip
```
