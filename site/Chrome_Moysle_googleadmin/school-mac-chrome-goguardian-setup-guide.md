# School Mac, Chrome, Mosyle, and GoGuardian Setup Guide

Last reviewed: May 2026

This guide assumes the school is managing Macs with Mosyle, using Google Workspace / Google Admin for Chrome, and using GoGuardian for student web filtering and classroom visibility.

## Executive Baseline

Use Mosyle for Mac ownership, OS security, local account controls, app deployment, and device compliance. Use Google Admin for Chrome browser policy, user sign-in policy, extensions, and Chrome reporting. Use GoGuardian for student filtering and classroom management. Do not rely on GoGuardian alone for Mac security because it primarily controls web activity through Chrome/browser and DNS/filtering products, not the entire macOS endpoint.

Recommended default:

| Area | Standard |
| --- | --- |
| Ownership | All school-owned Macs assigned in Apple School Manager and enrolled by Automated Device Enrollment into Mosyle |
| macOS version | Keep Macs on a current supported macOS release; enforce security updates quickly |
| Disk encryption | FileVault required, with personal recovery key escrowed in Mosyle |
| Local admin | Students: no local admin. Staff: standard user by default; use temporary elevation only when required |
| Apps | Install and patch Chrome, GoGuardian-required components, printers, productivity apps, and security tools through Mosyle |
| Chrome management | Enroll Chrome browsers or enforce user policies through Google Admin; verify with `chrome://policy` |
| Extensions | Force-install required GoGuardian and school extensions; block extension installation except an approved allowlist |
| Filtering | Apply student filtering through GoGuardian by OU/group and time/context; keep core CIPA/safety rules non-overridable |
| Privacy | Publish a clear school notice explaining what is monitored, when, on which accounts/devices, and who can access reports |

## 1. Build the Admin Structure First

Create matching structure across Apple School Manager, Mosyle, Google Admin, and GoGuardian:

| Group | Use |
| --- | --- |
| Students - Elementary | Restrictive Chrome, app, filtering, sharing, and extension policies |
| Students - Middle | Similar to elementary with grade-appropriate allowlists |
| Students - High | More academic access, still no unmanaged extensions or local admin |
| Teachers | Less restrictive filtering, classroom GoGuardian access, standard Mac user |
| Staff/Admin | Separate Chrome and filtering policy; never mix with student OUs |
| IT Test | Receives changes first for 3-5 school days |
| Loaner/Shared Macs | Kiosk/shared-device settings, aggressive reset and sign-out policy |

Rule: test every new policy in `IT Test`, then a small pilot group, then production. Most bad rollouts come from applying browser, extension, or login restrictions directly to the root OU.

## 2. Mosyle Mac Setup

### Apple School Manager and Enrollment

1. In Apple School Manager, confirm all school-owned Macs are assigned to Mosyle as the MDM server.
2. In Mosyle, create Automated Device Enrollment profiles for each Mac type: student, teacher, staff, shared/lab.
3. Require MDM enrollment during Setup Assistant.
4. Prevent users from removing the MDM profile on school-owned devices.
5. Skip consumer setup panes that are not needed, such as personal Apple ID prompts, Siri, Screen Time, Touch ID setup if your policy does not allow it, and unnecessary diagnostics prompts.

### Identity and Accounts

Recommended:

1. Use Google Workspace SSO with Mosyle Auth if licensed and supported in your environment.
2. Create local accounts automatically during enrollment.
3. Keep users as standard users.
4. Reserve local admin for IT accounts only.
5. Use temporary admin elevation or Mosyle privilege management for staff software needs instead of permanent admin rights.
6. Disable guest login.
7. Require password after sleep/screensaver.
8. Set screen lock timeout:
   - Students: 5-10 minutes
   - Staff: 10-15 minutes
   - Shared/lab: 5 minutes

### FileVault

Enforce FileVault on all portable Macs.

Settings to use:

1. Enable FileVault during or immediately after enrollment.
2. Escrow the personal recovery key to Mosyle.
3. Rotate recovery keys when a Mac changes owner or leaves repair.
4. Report weekly on FileVault status.
5. Treat "FileVault off" or "recovery key not escrowed" as non-compliant.

Verification:

```bash
fdesetup status
```

Expected: `FileVault is On.`

### Activation Lock

Recommended:

1. Disable personal Apple ID Activation Lock on school-owned Macs where possible.
2. Ensure Mosyle stores an Activation Lock bypass code when Activation Lock can be managed.
3. Before repair, disposal, or reassignment, clear Activation Lock and verify the Mac is released from the previous user.

### OS Updates

Recommended enforcement:

| Update type | Deadline |
| --- | --- |
| Critical security updates / Rapid Security Responses / background security content | Same day to 3 days |
| Minor macOS updates | 7 days after validation |
| Major macOS upgrades | Pilot first, then deploy by semester or summer maintenance window |

Use Mosyle OS update workflows to define minimum OS versions, user deferral windows, restart timing, and enforcement. Avoid indefinite deferrals.

### Built-In macOS Protections

Keep these enabled:

1. Gatekeeper.
2. XProtect and background security updates.
3. System Integrity Protection.
4. Firewall for staff/student laptops unless a required service conflicts.
5. Automatic time sync.
6. Secure screen lock.
7. Standard user accounts.

Avoid:

1. Disabling Gatekeeper to make app deployment easier.
2. Giving students admin rights.
3. Allowing unmanaged kernel/system extensions.
4. Letting users install browser extensions freely.

### App Deployment

Deploy through Mosyle:

1. Google Chrome.
2. Google Drive for desktop if used.
3. GoGuardian-required apps/extensions/configuration as directed by GoGuardian.
4. Printers and printer drivers.
5. Zoom/Teams/Meet helper apps if needed.
6. Accessibility, PPPC, system extension, and network extension profiles required by approved apps.

Patch standard:

1. Auto-update Chrome.
2. Auto-patch common apps through Mosyle app catalog or managed PKG workflows.
3. Remove apps that are no longer approved.
4. Keep a small exception list for apps that must be version-pinned for testing or curriculum.

## 3. Google Admin: Chrome Setup

Google gives two major policy paths:

1. User policies: apply when a user signs into Chrome with a managed school account.
2. Enrolled browser policies: apply to Chrome on a managed Mac even before sign-in.

Recommended for school Macs: use both. Enroll Chrome browsers for device-level controls, and use user policies for student/staff differences.

### Core Chrome Policies

Set in Google Admin:

`Devices > Chrome > Settings > Users & browsers`

Recommended student settings:

| Policy area | Recommendation |
| --- | --- |
| Browser sign-in | Require users to sign into Chrome with a school account |
| Sync | Allow only school account sync; restrict personal account use |
| Incognito | Disable for students |
| Guest mode | Disable |
| Browser history | Do not allow students to clear history if required for investigations/reporting |
| Safe Browsing | Enhanced or standard protection required |
| Password manager | Usually disable for students; decide separately for staff |
| Autofill payment methods | Disable |
| Third-party extensions | Block by default, allowlist approved extensions only |
| Developer tools | Disable for younger students; allow only where curriculum requires |
| URL blocking | Use for known bypass/proxy categories in addition to GoGuardian |
| Downloads | Consider restricting risky file types; define safe download location |
| Printing | Allow only approved printers or managed print workflow |

Useful Chrome policy names to verify in `chrome://policy`:

| Goal | Chrome policy to look for |
| --- | --- |
| Require or control browser sign-in | `BrowserSignin` |
| Restrict allowed sign-in accounts | `RestrictSigninToPattern` |
| Disable guest mode | `BrowserGuestModeEnabled` |
| Disable incognito | `IncognitoModeAvailability` |
| Force-install extensions | `ExtensionInstallForcelist` or `ExtensionSettings` |
| Block extension installation by default | `ExtensionInstallBlocklist` or `ExtensionSettings` |
| Allow specific extensions | `ExtensionInstallAllowlist` or `ExtensionSettings` |
| Block URLs | `URLBlocklist` |
| Allow URL exceptions | `URLAllowlist` |
| Control Safe Browsing | `SafeBrowsingProtectionLevel` |
| Control password manager | `PasswordManagerEnabled` |

Recommended staff settings:

1. Require school account sign-in for managed Chrome profile.
2. Allow a broader extension allowlist, not open installation.
3. Keep Safe Browsing enabled.
4. Allow incognito only if your privacy and records policy permits it.
5. Separate staff from students in both Google Admin and GoGuardian.

### Extension Control

Set in:

`Devices > Chrome > Apps & extensions`

Recommended:

1. Force-install GoGuardian extensions required for your products.
2. Force-install only essential school extensions.
3. Set default extension installation to blocked for students.
4. Maintain an allowlist for curriculum tools.
5. Block extensions by risky permissions where available.
6. Do not let students remove force-installed extensions.
7. Test every extension with `chrome://policy` and `chrome://extensions`.

Deployment steps:

1. Apply to `IT Test`.
2. Sign into a managed student account on a test Mac.
3. Open `chrome://policy`.
4. Click **Reload policies**.
5. Confirm the extension policy source and values.
6. Open `chrome://extensions`.
7. Confirm the extension is installed and cannot be removed.
8. Move to pilot OU.
9. Move to production.

### Chrome Browser Enrollment on Macs

Use Chrome Enterprise Core / Chrome Browser Cloud Management when possible.

Recommended:

1. Enroll Chrome browser on all school-owned Macs.
2. Use Mosyle to deploy enrollment token/profile.
3. Apply device-level policies for security settings that should work even when the user is not signed in.
4. Use Google Admin reporting to track Chrome version, extensions, and policy status.

## 4. GoGuardian Setup

Use GoGuardian for web filtering, classroom management, and reporting. Keep the policy model simple enough that IT can explain it and troubleshoot it.

### GoGuardian Policy Structure

Recommended layers:

| Layer | Purpose |
| --- | --- |
| Root student safety policy | CIPA/safety categories, explicit content, malware, phishing, proxies, anonymizers; not teacher-overridable |
| Grade-band policies | Age-appropriate restrictions and allowlists |
| Class/session policies | Teacher classroom focus rules |
| Temporary exception groups | Short-lived access for testing, events, or specific assignments |
| Staff policy | Less restrictive, separate from student policies |

Important: keep core safety and compliance blocks at the root or non-overridable layer. GoGuardian itself recommends using teacher override only on policies applied at individual OU level while keeping CIPA-compliant policies non-overridable at the root.

### Filtering Standards

Block for students:

1. Adult/explicit content.
2. Malware, phishing, spam, and suspicious domains.
3. Proxy, VPN, anonymizer, and bypass sites.
4. Gambling and illegal drug content.
5. High-risk AI/chat/social categories according to school policy and grade level.
6. Chrome Web Store except approved extensions.
7. Unapproved browser downloads.

Allow:

1. District learning platforms.
2. Google Workspace services needed by grade.
3. State testing domains.
4. Library/research databases.
5. Accessibility and assistive technology services.
6. Curriculum-specific services by group, not globally.

### GoGuardian and Mac Reality Check

On Macs, students can potentially use browsers other than Chrome unless you control app installation and browser access with Mosyle. If the school expects GoGuardian Chrome extension coverage to be the primary control, then:

1. Force Chrome as the student browser.
2. Prevent students from installing other browsers.
3. Remove or restrict unmanaged browsers.
4. Consider GoGuardian DNS or network-layer filtering for broader device coverage if licensed.
5. Keep Mosyle restrictions aligned with GoGuardian expectations.

## 5. Recommended Mosyle Restrictions for Student Macs

Apply to student Mac OUs:

| Setting | Recommendation |
| --- | --- |
| Local admin | Disabled |
| Guest account | Disabled |
| App Store | Restrict installs unless managed |
| System Settings | Restrict high-risk panes where practical |
| Profiles | Prevent removal |
| AirDrop | Disable or restrict if not needed |
| iCloud Drive | Disable for students unless explicitly approved |
| Personal Apple ID | Avoid on shared/student-owned school Macs |
| External drives | Decide by grade; restrict for younger/shared devices |
| Sharing services | Disable Remote Login, Screen Sharing, File Sharing unless IT-managed |
| Firewall | Enabled |
| Printers | Managed list only |
| Browsers | Chrome managed; unapproved browsers blocked or removed |

## 6. Optional Compliance Benchmark

For a stronger formal hardening target, use the NIST macOS Security Compliance Project (mSCP) as the reference baseline, then tailor it for school operations before enforcement.

Practical school approach:

1. Start with the built-in security baseline in this guide.
2. Compare it with the current mSCP guidance for your macOS version.
3. Pilot stricter settings before enforcing them globally.
4. Avoid applying a full STIG-style baseline to student or teacher Macs without testing, because some controls can disrupt classroom tools, accessibility workflows, printing, video conferencing, or state testing.
5. Keep a documented exception list for settings that are not compatible with instruction or testing.

## 7. Staff Mac Standards

Staff need fewer classroom restrictions but the same device security baseline.

Recommended:

1. FileVault on.
2. Standard user account by default.
3. Temporary admin workflow for approved changes.
4. Chrome managed with staff OU policy.
5. GoGuardian staff policy if the school filters staff devices.
6. Approved extension allowlist.
7. Password/passkey/MFA standards enforced in Google Workspace.
8. No shared staff accounts.

## 8. Verification Checklist

Run this before full rollout.

### On a Test Mac

1. Mac appears in Mosyle under correct group.
2. MDM profile is installed and non-removable.
3. FileVault is on.
4. Recovery key is escrowed in Mosyle.
5. User is standard, not admin.
6. Chrome is installed and current.
7. Required profiles are installed.
8. Unapproved apps cannot be installed by a student.
9. Firewall and Gatekeeper are enabled.

### In Chrome

1. Student must use school account.
2. Personal account sign-in is blocked or restricted.
3. GoGuardian extension is force-installed.
4. Student cannot remove required extensions.
5. Incognito/guest browsing is disabled for students.
6. `chrome://policy` shows expected policies.
7. `chrome://extensions` shows required extensions.

### In GoGuardian

1. Student appears in correct OU/group.
2. Filtering policy applies on campus.
3. Filtering policy applies off campus if intended/licensed.
4. Block page appears for blocked test categories.
5. Teacher session works for a pilot classroom.
6. Teacher override works only where allowed.
7. Reports/audit logs are visible only to approved roles.

## 9. Rollout Plan

### Week 1: Design

1. Confirm OUs/groups.
2. Decide student/staff privacy notice.
3. Decide filtering categories and exceptions.
4. Build Mosyle, Google Admin, and GoGuardian test groups.

### Week 2: Technical Pilot

1. Enroll 3-5 IT/test Macs.
2. Apply Mac baseline.
3. Apply Chrome policies.
4. Deploy GoGuardian extensions.
5. Validate update, login, FileVault, and filtering behavior.

### Week 3: Classroom Pilot

1. Pilot one class per grade band.
2. Collect blocked-site requests.
3. Adjust allowlists by group.
4. Train teachers on GoGuardian Teacher boundaries.

### Week 4: Production

1. Roll out by grade or campus.
2. Monitor FileVault, Chrome policy, extension, and GoGuardian reports daily.
3. Keep a rollback group and known-good policy backup.

## 10. Ongoing Operations

Weekly:

1. Review Macs missing FileVault, current OS, or MDM check-in.
2. Review Chrome versions and extension inventory.
3. Review GoGuardian top blocked categories and bypass attempts.
4. Review exception groups and remove expired exceptions.

Monthly:

1. Audit local admin accounts.
2. Audit staff and GoGuardian role permissions.
3. Review new extension/app requests.
4. Check stale devices in Mosyle and Google Admin.

Each semester:

1. Review privacy notice and acceptable use policy.
2. Re-test enrollment workflow.
3. Re-test lost/stolen Mac process.
4. Review OS upgrade readiness.
5. Clean up unused policies, groups, and allowlists.

## 11. Source References

Primary references used:

1. Apple Platform Deployment: software updates through MDM and Apple Software Lookup Service: https://support.apple.com/guide/deployment/depafd2fad80/web
2. Apple Platform Deployment: MDM security queries for FileVault and Activation Lock: https://support.apple.com/guide/deployment/dep5872f7b3c/web
3. Apple Platform Security: Gatekeeper and runtime protection: https://support.apple.com/guide/security/sec5599b66df/web
4. Apple Platform Security: XProtect and malware protection: https://support.apple.com/guide/security/sec469d47bd8/web
5. Google Chrome Enterprise: set Chrome policies for users or browsers: https://support.google.com/chrome/a/answer/2657289
6. Google Chrome Enterprise: force-install apps and extensions: https://support.google.com/chrome/a/answer/6306504
7. Google Chrome Enterprise: view current Chrome policies with `chrome://policy`: https://support.google.com/chrome/a/answer/9024365
8. Google Chrome Enterprise: app and extension policy overview: https://support.google.com/chrome/a/answer/7666985
9. Mosyle product/security capabilities for macOS management, FileVault workflows, OS updates, app patching, and Chrome management: https://business.mosyle.com/security/
10. Mosyle product overview for Apple device management, Apple School/Business Manager integration, Mosyle Auth, FileVault enablement, and app patching: https://business.mosyle.com/
11. GoGuardian Admin product information for filtering across ChromeOS, Windows, and macOS, policy controls, reporting, and DNS protection: https://www.goguardian.com/admin
12. GoGuardian Teacher Override Filtering note on keeping CIPA-compliant root policies non-overridable: https://www.goguardian.com/product-update/teacher-override-filtering
13. GoGuardian installation guide note for deploying extensions and Google Admin settings through Org Management: https://www.goguardian.com/product-update/installation-guide-in-org-management
14. NIST macOS Security Compliance Project for current macOS hardening baselines and generated guidance: https://pages.nist.gov/macos_security/
