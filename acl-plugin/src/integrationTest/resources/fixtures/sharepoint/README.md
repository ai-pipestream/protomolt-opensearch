# SharePoint ACL fixture

Made by protomolt's `SharePointSecurityMappingTest` (commit 75e5e2d) from grpc-microsoft Sync records with
`include_security`, recorded live on the WelcomeToPipestream test site (run 45073949282), with tenant, site and
account identifiers scrubbed.

- `sharepoint-items.ndjson`: one line per drive, list or item, protomolt `DocumentSecurity` projected into the
  plugin's ACL fields. SharePoint has no deny rules and no gates, so `acl_deny` and `acl_gates` are empty.
- `sharepoint-callers.json`: per caller, the expanded and lower-cased principal keys and protomolt's own
  `DocumentAccessPolicy` read decision for every item. One caller holds only a Limited Access group, which grants no
  read.

Regenerate in protomolt and copy both files here; do not edit them by hand.
