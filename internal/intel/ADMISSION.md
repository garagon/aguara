# OSV admission

An advisory mentioning malware does not establish that its affected package is
malicious. The importer accepts MAL namespace records and structurally parsed
OpenSSF origins. Exact-version entries also accept GitHub-reviewed CWE-506
(Embedded Malicious Code). This does not broaden the range-admission channels.

Some historical GHSA advisories lack that structured classification. The
`reviewed_osv.json` compatibility list preserves reviewed exact tuples, never
all future versions or other packages under the same advisory ID. Each entry
records its OSV API source and the SHA-256 of the raw response inspected on
2026-09-10. Version lists were intersected with the existing embedded and retained
2026-09-07 snapshots; no versions were inferred from summaries or ranges.

The review included historical credential-stealing browser packages, unauthorized
releases, and structured GitHub CWE-506 records. PYSEC-2026-206 is excluded:
its version list includes guardrails-ai 0.10.0, which its own report identifies
as unaffected. GHSA-xmpw-2vmm-p4p6 preserves the malicious 0.10.1 release.
GHSA-cxm3-wv7p-598c was not grandfathered: OSV marks it withdrawn on 2026-07-28.
Its MAL counterparts are unaffected by that exclusion.

To add a compatibility entry, inspect the original advisory, verify that it
describes malicious code in the named package (not a vulnerability exploitable
by a different malicious package), and verify each exact version. Record the
source response digest and add positive and clean-neighbor tests. Do not turn
summary keywords, URLs, CVE aliases or the GHSA prefix into an authorization rule.

Generated snapshots carry `admission_policy: 1`. This is classification metadata,
not a signature. Downloads still require the existing verification or explicit
insecure opt-in. Legacy/unknown-policy OSV snapshots are filtered before use:
MAL entries and real withdrawal records remain; other live records are restricted
to the reviewed tuples with ranges removed. Source labels cannot exempt a mixed
snapshot. The separate built-in manual snapshot is not filtered.

This runtime migration covers the embedded blob, verified local cache and freshly
downloaded data without changing signed bytes or rewriting the committed blob.
It protects both matching and raw-record filename checks. Older binaries do not
apply this policy; users need an updated binary, not only an intel refresh.
