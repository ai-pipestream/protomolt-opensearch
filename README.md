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

This needs the cluster permission `cluster:admin/protomolt/acl/principals/put`.

Each node caches a caller's stored keys after reading them:

| Setting | Default | Meaning |
| --- | --- | --- |
| `protomolt.acl.principals.cache_ttl` | `30s` | How long a node keeps a caller's keys. `0` reads the store on every protected request. |
| `protomolt.acl.principals.cache_max_entries` | `100000` | How many callers a node keeps. |

A put clears the caller from the cache of the node that handled it, so that node applies new keys at once. Other
nodes apply them when their entry expires, so a removed key can still grant reads on another node for up to
`cache_ttl`.

A caller's login and stored keys together must not exceed the protected index's `index.max_terms_count` (65536 by
default); a search by a caller over that limit fails with 400 and returns nothing.

### Searches

- `_search`, `_count` and `_msearch` on a protected index get the access filter. Unprotected indices in the same
  request are not filtered.
- When the plugin cannot tell which indices a search reaches (for example cross-cluster searches), every index in it
  is filtered.
- `suggest`, `global` aggregations, `significant_text` aggregations and `explain: true` are rejected on protected
  indices.
- `significant_terms` aggregations get the access filter added to their background filter, so background counts only
  cover documents the caller can read.
- get, mget and term vectors return a document the caller may not read as not found. The ACL fields are read with an
  internal realtime multi get, so source filtering on the request does not skip the check.
- The explain API, term statistics, field statistics (term vectors need `"field_statistics": false`), artificial
  documents and multi term vectors are rejected on protected indices.

### What index statistics still show

Lucene keeps term statistics per shard, for every document in it. The plugin filters which documents match, not the
statistics, so:

- Scores (BM25 idf and length norms) are computed from all documents of the shard. For a term that occurs in a
  document the caller can read, the score shows roughly how many hidden documents also contain it. In
  `ScoreStatisticsIT`, one readable document scores 0.1308 for `budget` alone in an index and 0.0035 next to 50
  hidden documents containing `budget`. Built-in document-level security shows the same shift.
- A term that occurs in no readable document adds nothing to any score, so its use in hidden documents cannot be
  probed through scores.
- Built-in document-level security also shows hidden documents in `significant_terms` and `significant_text`
  background counts (`bg_count` 51 for 1 readable document in the same test). The plugin does not.

Ways to remove the score signal, none of them built yet: keep each security domain (for example a Confluence space or
SharePoint site) in its own index or shard so statistics only cover documents with the same readers; or score
protected indices without term statistics (constant score), at the cost of relevance ranking.

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
- `RealExhaustiveAclIT` runs protomolt's exhaustive fixture the same way: 64 callers (every subset of six identities)
  against documents with deny rules, a gate, write-only rules and no rules.
- `GeneratedAclScaleIT` indexes 20,000 generated documents with random allow, deny and gate keys and checks that
  callers with 5, 500, 5,000 and 65,535 keys get exactly the documents the ACL rule allows by search and get, and that
  a caller over `index.max_terms_count` is refused. It writes median timings to
  `acl-plugin/build/reports/acl-scale/timings.txt`.
- `ScoreStatisticsIT` checks the statistics rules above and records the numbers to
  `acl-plugin/build/reports/acl-scale/score-statistics.txt`.
- `DlsComparisonIT` runs the same documents through the plugin and through built-in document-level security (a terms
  lookup into a principals index) and records where they differ. Docker is required. Any compiler, javadoc or Gradle deprecation
warning fails the build.

Install on a node:

```
bin/opensearch-plugin install file:///path/to/protomolt-acl-<version>-os3.10.0.zip
```
