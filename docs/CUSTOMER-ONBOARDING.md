# Complimentary customer onboarding

Deployed October 8, 2026 as source `793a5116d89cb5518f3546ae3faaddd2be3c2528`. Lewis Dental Group (`lewisdentalgrp.com`, workspace 8) is created under the requested owner with approved admin membership and complimentary onboarding. First review: November 7, 2026 at 16:04:25 UTC (11:04:25 Eastern). DNS ownership remains pending; onboarding controls are active.

## Admin workflow

Use **Add or join workspace → Add a customer**. Platform administrators see **Onboarding — complimentary access for 30 days, without DNS changes** and a reason field. Each new domain gets an independent workspace, the normal domain verification challenge, daily public checks and a dated 30-day onboarding approval. DNS ownership remains pending; no DNS records are changed by this workflow.

The same dialog includes **Customer onboarding**, listing existing customer workspaces administered by the signed-in platform administrator. **Approve onboarding for 30 days** starts a transition for an existing customer, **Reapprove for 30 days** renews an expired approval, and **End onboarding** ends that exception. Every decision requires a reason and records the actor, version and deadline in the workspace audit log.

At the deadline, the platform admin dashboard presents a review popup across their approved customer workspaces, regardless of which customer is selected. Each customer can be reapproved or ended separately. **Review later** or Escape postpones the popup for the current page session; the customer remains due and the popup returns on refresh or a new session. New due customers cause a new prompt. The page checks once per minute while visible; reopening the customer dialog also refreshes the list. A closed browser cannot display a popup; due records remain available on the next visit and the scheduler creates a durable workspace notification once per approval version.

An expired or ended onboarding grant stops providing the DNS exception. For an otherwise unverified workspace, scanner enrollment, scan commands, active website assessment and member sharing controls close. Queued scans are cancelled and active scans receive the existing cancellation request. Saved reports, established memberships and ordinary public DNS/website checks remain available. A separately verified domain or another valid pre-existing override continues to supply its own authorization. Renewing a customer does not resume cancelled scans automatically.

## Authority and isolation

The configured `DAEDALUS_PLATFORM_ADMIN_EMAILS` list controls this feature; the requested owner is `sean.dolbec@cybersecuritypilot.org`. Configuration must include that existing authenticated account before rollout. Each listed customer also requires an approved admin membership. Normal customer admins cannot grant themselves onboarding, and workspace-scoped access keys cannot list or change the platform queue. Mutations reject cross-origin requests. Reviews carry an expected version; stale submissions cannot overwrite a newer decision.

Complimentary status records the free onboarding decision. There is no payment or subscription billing system in the present application; ending onboarding creates no charge and does not automatically enroll a customer into a paid plan. Google Admin audits continue to require actual domain verification, a dedicated read-only OAuth grant and tenant validation. The onboarding exception does not satisfy those Google requirements or establish ownership of the domain.

## Rollout and acceptance

- Local checks cover the 30-day grant, unchanged ownership status, expiry, repeat-notice suppression, explicit renewal, stale decisions, ending onboarding, verified controls, admin membership, cross-origin rejection and scoped access keys.
- Production rollout requires the normal clean, pushed release and verified off-host backup through `scripts/deploy_incus.py`, followed by readiness checks. A new `customer_onboarding` table is created through existing metadata initialization; existing organization columns and 14-day override rows are unchanged.
- Confirm the requested owner is configured as a platform admin. Create Lewis Dental Group for `lewisdentalgrp.com` through the normal customer flow, or approve onboarding on its existing workspace if already present. Verify the owner membership, persisted grant and 30-day deadline before claiming creation.
- Review the populated admin dialog and due popup on desktop/mobile, keyboard navigation, page refresh and real expiry/renewal behavior. Local API/template tests do not establish production or browser visual acceptance.

Local validation receipt: `validation/customer-onboarding-20261008/receipt.json` (ignored/private). Full suite: **1,114 passed, one skipped, 342 subtests**. Nine onboarding backend/UI checks passed; the UI check executes popup dismissal, new-due-customer prompting and reapproval through a DOM fixture. JavaScript syntax and diff whitespace passed. Release file selection includes both new modules. Actual populated browser visuals and production acceptance remain pending.

Production rollout passed internal/public readiness after verified off-host backup `daedalus-data-20261008T160335Z.tar.gz`. The 98-file release digest is `f60dd82aaa774062e1b71b8b6546834d99656d1f115f2d6e0f6c7af256f11992`. Owner workspace-list database projection includes Lewis exactly once; its creation, approval and owner-requested provisioning are audited. Public onboarding/dashboard scripts match tested source. Live browser visual review and a real future 30-day renewal remain separate acceptance checks.
