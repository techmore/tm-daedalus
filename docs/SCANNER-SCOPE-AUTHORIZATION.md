# Scanner authorization at dispatch

The scanner bridge checks every `start_scan` against a fresh authenticated portal heartbeat before emitting a scan to NmapUI. Private address syntax and the address-count limit are checked first; hostnames, public targets and oversized ranges never trigger dispatch.

An unknown, omitted, malformed or empty approved scope grants no permission. A failed heartbeat cannot reuse a cached grant. This includes older enrollment files with no `authorized_networks`, revoked scopes and permission changes since enrollment. A valid current scope can authorize an in-range target; it does not expand authorization to other networks. Enrollment credentials and saved results are unchanged.

## Rollout order

Deploy and verify the portal version that returns `authorized_networks` in authenticated heartbeat responses before upgrading installed bridges. An older portal that omits this field cannot authorize new scans through an updated bridge. During a portal outage, new remote scan commands fail rather than running under old permissions; existing collection/history is not erased.

The change is covered by bridge dispatch, malformed heartbeat, legacy enrollment, offline/revocation, legitimate scope change, command-journal deduplication and portal scope tests. These are isolated tests; no customer network scan or installed bridge upgrade was performed for this change. Physical rollout and acceptance remain part of deployment gates #11 and #15.

Tracking: [fail closed on unknown scope](https://github.com/techmore/tm-daedalus/issues/12).
