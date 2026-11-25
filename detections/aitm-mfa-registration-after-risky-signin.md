Detection: New MFA Method Registered After a Risky Sign-in

| Field | Detail |
| "Detection name" | MFA registration shortly after a risky sign-in (possible AiTM persistence) |
| "Platform" | Microsoft Sentinel / Log Analytics (KQL) |
| "Data sources" | `SigninLogs`, `AuditLogs` (Microsoft Entra ID) |
| "Severity" | High |
| "MITRE ATT&CK" | [T1556.006 Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/), [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| "Status" | Draft. Not yet tested against real or simulated data |

1. What it detects

After an attacker steals a session through an AiTM attack, a common next move is *persistence*: registering their own MFA method (such as a new authenticator app or phone number) so they keep access even if the stolen session is revoked or the password is reset.

This rule looks for a *successful sign-in flagged as risky*, followed within one hour by a *new security info (MFA method) registration* for the same user.

2. Query (KQL)

kql
// New MFA method registered within 1 hour after a risky successful sign-in
let lookback = 1h;
let RiskySignins = SigninLogs
    | where ResultType == "0"
    | where RiskLevelDuringSignIn in ("medium", "high")
    | project SigninTime = TimeGenerated,
              UserKey = tolower(UserPrincipalName),
              SigninIP = IPAddress,
              RiskLevelDuringSignIn;
let MfaChanges = AuditLogs
    | where OperationName == "User registered security info"
    | where Result == "success"
    | project ChangeTime = TimeGenerated,
              UserKey = tolower(tostring(InitiatedBy.user.userPrincipalName)),
              ChangeIP = tostring(InitiatedBy.user.ipAddress);
RiskySignins
| join kind=inner MfaChanges on UserKey
| where ChangeTime between (SigninTime .. (SigninTime + lookback))
| project UserKey, SigninTime, SigninIP, RiskLevelDuringSignIn, ChangeTime, ChangeIP
| order by ChangeTime desc

3. How it works

1. Collects successful sign-ins that the identity provider rated medium or high risk.
2. Collects successful "User registered security info" audit events.
3. Joins them on the user.
4. Keeps only cases where the MFA registration happened within the lookback window after the risky sign-in.

4. Requirements and assumptions

- Risk levels in sign-in logs depend on Microsoft Entra ID Protection. Check Microsoft's current documentation for the license required, and whether risk data appears in your environment.
- If you don't have risk data, you can substitute a different "suspicious sign-in" condition, for example the output of the [session reuse detection](aitm-session-reuse.md).
- The audit operation name and field layout should be confirmed against your own `AuditLogs` data, since schemas and wording can change.

5. Known false positives

| Cause | Why it triggers | How to handle |
| New employee onboarding | A first-time MFA setup can coincide with an unfamiliar sign-in | Exclude accounts created in the last few days, or users with no prior MFA methods |
| Legitimate travel or a new device | Risky sign-in, then the user adds a phone | Verify with the user; compare the registration IP with the sign-in IP |
| Helpdesk-assisted resets | An admin helps a user re-register | Exclude known helpdesk workflows and review `InitiatedBy` |

6. Tuning ideas
- Raise severity when the registration IP differs from the user's usual locations.
- Raise severity when the registration IP matches the risky sign-in IP.
- Add related audit operations, for example MFA method deleted or default method changed.
- Adjust `lookback` (for example 30 minutes or 4 hours) based on observed behavior.

7. Analyst response checklist

1. Contact the user through a trusted channel (not email from the suspect session) and confirm whether they registered the method.
2. Review the new method's type and when it was added.
3. If unexpected: **remove the new MFA method**, **revoke all sessions**, and reset the password.
4. Check for follow-on activity: inbox rules, mail forwarding, file downloads, further phishing from the account.
5. Review the original risky sign-in for the phishing source.
6. Document findings and update tuning notes.

8. Limitations

- Depends on risk scoring being available and accurate; attackers may avoid being flagged.
- A registration that happens outside the lookback window will be missed.
- Attackers can also persist by other means (for example OAuth app consent or inbox rules), which this rule does not cover.

9. Testing plan

- [x] Run the test file against synthetic data (see `tests/aitm-mfa-registration-test.kql`)
- [x] Record results and screenshot to `evidence/`
- [x] Tested on synthetic data (Azure Data Explorer free cluster)
- [x] [Test result: only bob@contoso.test is flagged](evidence/aitm-mfa-registration-result.png)
