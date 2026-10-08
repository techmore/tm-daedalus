# Website hosting inventory and cost estimates

Reviewed October 8, 2026. Amounts are USD. This inventory covers Lewis Dental Group and the existing CSP/BFS reporting targets, including the separate Daedalus portal. It records public hosting evidence and planning scenarios; it does not establish a customer's actual bill.

## Hosting inventory

| Website / pages | Hosting and platform evidence | DNS / public edge | Location and confidence |
| --- | --- | --- | --- |
| [Lewis Dental Group](https://www.lewisdentalgrp.com/) and its patient, dentistry and office pages | `www` CNAME is `clients.pbhshosting.com`; assets load from `www.pbhshosting.com`; footer credits PBHS. WordPress-style `wp-content` assets and PBHS plugins are observed. PBHS-managed hosting is strongly supported. | NS: `ns1.pbhsdns.com`, `ns2.pbhsdns.com`. Apex A: `104.21.38.121`, `172.67.222.161`. HTTP HEAD returns Cloudflare headers and 403, while the browser loads the site. | Cloudflare edge addresses do not identify the origin server or its physical region. Origin region, underlying infrastructure vendor and contractual data residency remain unconfirmed. |
| [Buckingham Friends School](https://www.bfs.org/) | `www` CNAME is `sites.edliocloud.com`. This supports Edlio as the website platform/hosting service. | NS: `ns1.edlio.com`, `ns2.edlio.com`. Apex returns Cloudflare-range addresses including `104.18.189.233`, `104.18.190.233`, `104.16.158.133`, `104.16.159.133`. | Platform identification has strong DNS evidence; origin region and contracted service tier are unknown. |
| [CSP marketing](https://cybersecuritypilot.org/), Daedalus overview and school resource pages under the same origin | GitHub Pages publishes repository `site/` through `.github/workflows/pages.yml`; documented in README. Apex resolves to four `185.199.108–111.153` GitHub Pages addresses. | NS: `ns1.hover.com`, `ns2.hover.com`. Hover DNS service is separate from GitHub website hosting. | GitHub Pages static hosting; no customer-selected origin region established. |
| [Daedalus portal](https://daedalus.cybersecuritypilot.org/) | Existing production deployment receipts identify the SER8 host, Incus instance `daedalus-prod`, `daedalus.service` and persistent application data. Python application, login and reports require this server. | Public HTTPS portal is reachable; the origin's routing and TLS transport are separate from the static marketing site. | SER8 is the documented machine, rather than a commercial hosting plan. Physical site, power allocation and internet cost are not verified by this inventory. Scanner instances are separate workloads. |

DNS was queried on October 8, 2026; detailed timestamped observations are retained in the ignored local validation receipt `validation/hosting-20261008/dns.json`. A CDN, DNS provider, registrar, website agency and origin host are separate roles. None of the public IP observations establishes the customer's purchased plan, origin location or paid Cloudflare tier.

## Cost estimate and assumptions

| Service / scenario | Monthly estimate | Annual estimate | Basis and remaining evidence |
| --- | ---: | ---: | --- |
| CSP static GitHub Pages hosting | $0 incremental hosting | $0 incremental hosting | GitHub Pages is included for public repositories on GitHub Free. Domain registration, paid account features and staff time are separate. This is hosting eligibility, not confirmation of all account charges. |
| Lewis current PBHS service | Quote / invoice required | Quote / invoice required | Public evidence identifies the provider but no current applicable website-hosting tariff was verified. PBHS SecureMail, TruForm and chat prices are separate products and must not be substituted for website hosting. |
| BFS current Edlio service | Quote / invoice required | Quote / invoice required | Edlio sells custom website packages; collect the current contract and renewal quote, including any communication/mobile/payment add-ons. A generic VM price does not estimate the Edlio subscription. |
| Reference infrastructure for a small self-managed website or portal | $14.40–$28.80 | $172.80–$345.60 | DigitalOcean Basic regular 2 GiB / 1 vCPU is $12/month; 4 GiB / 2 vCPU is $24/month. Add published weekly backups at 20%: $2.40–$4.80/month. This is a comparison scenario, not the current host or a migration recommendation. Size must be validated against workload. |
| Existing SER8 electricity illustration, whole machine | $2.19–$6.57 | $26.28–$78.84 | Assumed average draw 20–60 W, 730 hours/month and $0.15/kWh: watts / 1000 × hours × rate. Draw and tariff are assumptions, not measurements. Shared workloads require a documented allocation. Hardware amortization, storage, off-host backup, internet, UPS, support and taxes are additional. |

The reference VM estimate includes its published disk/transfer allowance and weekly backup percentage only. It excludes software maintenance, security operations, domain renewal, email, extra storage/transfer, high availability, marketing, design and patient-form services. It cannot be interpreted as equivalent to PBHS or Edlio's managed package. There is no defensible total current hosting bill until those contracts and the SER8 allocation are known.

Pricing references, checked October 8, 2026:

- [GitHub Pages availability and static hosting](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).
- [DigitalOcean Droplet plans and backup rates](https://www.digitalocean.com/pricing/droplets).
- [PBHS website services](https://www.pbhs.com/) and [website consultation](https://www.pbhs.com/consultation-form/); no applicable current website hosting rate confirmed.
- [Edlio website packages](https://www.edlio.com/websites) and [contract / sales contact](https://www.edlio.com/contact-us).

## Ongoing reporting method

Each reporting review should retain the observed hostname, page scope, DNS answers, provider roles, collection timestamp, evidence links, confidence and origin-location coverage. Pages under a common host share an inventory entry unless separate hosting is observed. Record provider or DNS changes separately from content changes; a failed request leaves coverage unavailable rather than proving a migration.

For costs retain currency, billing interval, plan, included services, usage assumptions, source date, contract renewal and whether the number is an actual invoice, vendor quote, published price or planning assumption. Keep invoices and personal account identifiers in the private workspace. Compare only equivalent service scopes; show recurring hosting, domain renewal, email, add-ons and one-time implementation separately. Recheck public prices at each reporting period and reconcile estimates to actual invoices when supplied.

The present delivery adds this inventory to the project reporting documentation. Automatic hosting-provider collection, cost fields and hosting-cost PDF/dashboard sections are not yet implemented. The existing DNS/web audit history supplies supporting evidence; it does not automatically populate this cost table.

## Lewis onboarding status

Requested workspace: Lewis Dental Group, apex `lewisdentalgrp.com`, website `https://www.lewisdentalgrp.com/`. The requested owner's Google account is recorded only in the private onboarding receipt. Production creation is pending deployment access and authenticated admin provisioning, with the requested 30-day onboarding workflow; this document does not claim that a workspace or membership was created. The normal domain TXT challenge and verification must remain in effect after creation. Adding a website domain does not prove that the domain uses Google Workspace or authorize Google Admin consent.
