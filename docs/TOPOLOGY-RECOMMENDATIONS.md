# Topology and addressing recommendations

New local NmapUI HTML/PDF reports append an advisory section to the existing stylesheet output. Newly requested Daedalus scanner PDFs opt into appendix version 1 in their saved template provenance. Previously saved Daedalus snapshots retain their rendering behavior.

The appendix separates observed responding IPv4 addresses from an illustrative /24 grouping. It does not claim to discover DHCP configuration, subnet masks, physical links, VLANs, device roles or free addresses. Nonresponding devices may still occupy proposed addresses.

The first recommendation is minimal disruption: preserve the subnet, gateway and working fixed addresses (including .10 servers); use verified DHCP reservations where supported for printers, infrastructure and selected fixed workstations. Example groupings include printers at .50–69 and dynamic clients at .100 and above. These are planning examples, conditional on the actual scope, exclusions and inventory. Manual static addresses must be excluded from dynamic allocation and documented.

Before/after diagrams describe logical address organization, with a separate future segmentation option. The report never applies network configuration changes. Confirm DHCP and DNS records, device ownership, print queues and address-based rules, then stage one change at a time with rollback information.

Implementation is committed in TM-NmapUI and bundled in Daedalus. This change has not yet been installed into the currently running scanner or deployed to SER8. No tests or PDF rendering checks were run for this addition.

## Firewall discovery-only control

Scan Rules now includes a saved, enabled-by-default “Discovery only for firewall / gateway” checkbox. Quick Scan keeps discovery and MAC/vendor inventory but excludes identified gateway addresses from service scanning. Comprehensive report scans exclude those addresses entirely; their discovery inventory comes from Quick Scan. Default IPv4 gateway and first private/public route hops supply the protected addresses. This is not automatic identification of every firewall: other firewall IPs must be explicitly excluded. Job details retain the effective protected-address list. The option applies to newly started scans after saving and is not retroactive to a running job. No tests were run for this addition.

Local activation: installed source release 0894a521cf904575f95036b1aa6da82fd8999fe386c3b3d98b3f8750f934f07b on 2026-10-12. The preceding scan was cancelled before its gateway phase. The checkbox was observed enabled, native app reloaded, and a new 10.20.0.0/24 run started at 08:17:08 EDT. This also installs the topology appendix source locally; no generated appendix PDF has been visually checked. SER8 application deployment remains pending.

## Opt-in behavior

Topology recommendations now default off. Local Settings → Report Exports includes a persisted “Include topology & address recommendations” checkbox used by both new scans and PDF generation from saved evidence. Daedalus run PDF actions have a separate default-off checkbox, remembered per scanner in that browser; the API independently defaults false and snapshots the chosen appendix version. Existing generated PDFs are unaffected. The current owner's local scanner is explicitly opted in during activation. No tests were run for this change.

## Customer/subnet device plans

Local target profiles now retain a normalized operational device plan and their own report opt-in. PDF profile lookup requires both the customer identity and a contained target subnet, so identical private subnets at different customers do not share plans. The dashboard displays the selected customer's exact-subnet map ahead of scan summary cards, including a saved per-profile PDF checkbox. Each device has a role, user-reported state, proposed address, logical parent and notes. Proposed assignments and operational dependencies are explicitly distinguished from measured IP/MAC identities and physical cabling. User-specific plan data is stored in local runtime settings, not this source repository. No IP assignments are applied. No automated tests were run for this addition.

Local activation completed: customer/subnet plan survived settings normalization, the authoritative customer selector loaded, and the operational map plus checked per-profile PDF option were observed in both the dashboard and the native Mac app. Customer-specific addresses remain in local runtime settings and the user's local map artifact. Local global report default is off. Production/SER8 deployment and visual review of a generated appendix PDF remain pending.
