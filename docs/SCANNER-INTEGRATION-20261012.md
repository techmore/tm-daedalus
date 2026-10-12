# Scanner integration — October 12, 2026

## Customer identity

New interactive scan jobs snapshot the server-side session's customer ID/name at start. Local history and run details project that saved identity; comparison rejects different customer identities even when their private subnet is identical. Existing unattributed runs remain unattributed. This does not infer historical ownership or implement cloud tenant reassignment.

## Mac raw ARP

The local Mac has an ARP-only helper at `/Library/PrivilegedHelperTools/DaedalusARP/scan`, installed using the system administrator authorization dialog. A validated account-specific sudoers entry permits this helper only. It validates bounded RFC1918 IPv4 targets and local `enN` interfaces, runs a protected copy of arp-scan and OUI data with a clean environment, and never elevates Nmap or the web backend. A subsequent `sudo -n` sweep completed with 21 responding devices and no password prompt.

The scanner source kit includes `packaging/macos/install-arp-helper.py`. Installation remains an explicit one-time administrator operation; it is not silently performed by normal upgrades. Homebrew updates do not replace the protected copy: rerun the installer to refresh it. This helper is separate from the full system-service installer and does not resolve Nmap SYN/OS-detection privileges.

## Hostnames and history

The installed scanner includes the compact history review and bounded, direct-client mDNS fallback. Device-reported names retain their source and are not directory-verified identities. Missing replies do not mean offline. NetBIOS and WS-Discovery were used manually during discovery but are not automatic fallback implementations yet.

## Validation limits

No new automated regression suite was run for these changes. Installer/helper syntax was parsed and prompt-free raw ARP exercised on the actual Mac. Customer attribution is being checked with a real scan of a user-confirmed client. PDF appendix visual review, full native-branch reconciliation and physical-host unattended soak remain separate open items.
