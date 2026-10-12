# Topology and addressing recommendations

New local NmapUI HTML/PDF reports append an advisory section to the existing stylesheet output. Newly requested Daedalus scanner PDFs opt into appendix version 1 in their saved template provenance. Previously saved Daedalus snapshots retain their rendering behavior.

The appendix separates observed responding IPv4 addresses from an illustrative /24 grouping. It does not claim to discover DHCP configuration, subnet masks, physical links, VLANs, device roles or free addresses. Nonresponding devices may still occupy proposed addresses.

The first recommendation is minimal disruption: preserve the subnet, gateway and working fixed addresses (including .10 servers); use verified DHCP reservations where supported for printers, infrastructure and selected fixed workstations. Example groupings include printers at .50–69 and dynamic clients at .100 and above. These are planning examples, conditional on the actual scope, exclusions and inventory. Manual static addresses must be excluded from dynamic allocation and documented.

Before/after diagrams describe logical address organization, with a separate future segmentation option. The report never applies network configuration changes. Confirm DHCP and DNS records, device ownership, print queues and address-based rules, then stage one change at a time with rollback information.

Implementation is committed in TM-NmapUI and bundled in Daedalus. This change has not yet been installed into the currently running scanner or deployed to SER8. No tests or PDF rendering checks were run for this addition.

## Firewall discovery-only control

Scan Rules now includes a saved, enabled-by-default “Discovery only for firewall / gateway” checkbox. Quick Scan keeps discovery and MAC/vendor inventory but excludes identified gateway addresses from service scanning. Comprehensive report scans exclude those addresses entirely; their discovery inventory comes from Quick Scan. Default IPv4 gateway and first private/public route hops supply the protected addresses. This is not automatic identification of every firewall: other firewall IPs must be explicitly excluded. Job details retain the effective protected-address list. The option applies to newly started scans after saving and is not retroactive to a running job. No tests were run for this addition.
