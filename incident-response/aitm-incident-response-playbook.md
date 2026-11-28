# Incident Response Playbook: Suspected AiTM Phishing Compromise
|11-20-26 | Tabletop (Solo) |Samson Oragbon| Summary: Staff should be trained constantly to enable them to keep up with the constant changes in the technological advancement even with the current AI revolution, environment should be hardened and minimum best practice should be adhered to in every organization. 
| Field | Detail |
| **Scenario** | A user's Microsoft 365 / Entra ID account is suspected compromised through Adversary-in-the-Middle (AiTM) phishing and session token theft |
| **Audience** | SOC analysts and IT administrators |
| **Status** | Draft, based on general incident response practice. Walked through once in a solo tabletop exercise (see tabletop-exercise-bob.md)
| **Related** | [How AiTM works](../docs/how-aitm-works.md) · [Session reuse detection](../detections/aitm-session-reuse.md) · [MFA registration detection](../detections/aitm-mfa-registration-after-risky-signin.md) · [Hardening guide](../hardening/aitm-hardening-guide.md) |

**Adapt before use.** Menu names, tools, and policies differ between organizations and change over time. Confirm each step against your current Microsoft documentation and your organization's incident response policy.

1. Process overview

flowchart LR
    A[1. Detect and triage] --> B[2. Contain]
    B --> C[3. Investigate scope]
    C --> D[4. Eradicate]
    D --> E[5. Recover]
    E --> F[6. Lessons learned]

2. Phase 1: Detect and triage

**Typical triggers**
- Alert from the [session reuse detection](../detections/aitm-session-reuse.md)
- Alert from the [MFA registration detection](../detections/aitm-mfa-registration-after-risky-signin.md)
- A user reports a suspicious login page, or says they entered credentials on an unexpected site
- Identity provider risk alerts
- Reports of strange emails sent from a colleague's account

**Triage questions**

| Question | Why it matters |

| Did the user click a link and sign in recently? | Confirms the likely entry point |
| Does the user recognize all recent sign-ins (location, device, app)? | Separates travel or VPN false positives from compromise |
| Were any MFA methods added or changed? | Indicates attacker persistence |
| Does the account have privileged roles? | Raises severity and urgency |

**Severity guide (adjust to your organization)**

| Level | Example |

| Low | Alert explained as VPN or travel, no suspicious follow-up activity |
| Medium | Unexplained session reuse, no evidence of data access |
| High | Confirmed attacker session, MFA change, inbox rules, or data access |
| Critical | Privileged or finance account compromised, or evidence of fraud attempts |

**Record from the start:** time of detection, alert source, affected user, analyst name, and a running timeline of every action taken.

3. Phase 2: Contain

**Goal:** cut off the attacker's access quickly, without destroying evidence.

Perform these in order, adjusting for your organization's policy:

1. **Preserve evidence first.** Export the relevant sign-in logs, audit logs, and mailbox activity for the user, since retention windows are limited.
2. **Block sign-in** for the affected account temporarily if the business can accept it. This freezes the situation while you work.
3. **Revoke all active sessions and refresh tokens** for the user.
4. **Reset the password** using a secure channel (not email from the possibly compromised account).
5. **Review and remove unrecognized MFA methods.** Do this carefully so that you don't remove the user's legitimate methods.
6. **Contact the user through a trusted channel** (phone call or in person), not through the suspect mailbox.

**Why order matters:** If you reset the password but leave an attacker-registered MFA method in place, the attacker can sign in again. Always check authentication methods as part of containment.

4. Phase 3: Investigate scope

**What did the attacker do after getting in?**

| Area | What to check |

| Sign-ins | All sign-ins for the account, with IPs, locations, user agents, and apps accessed |
| Authentication methods | New or changed MFA methods and when they were added |
| Mailbox rules | New inbox rules, especially those that forward, delete, or move messages |
| Mail forwarding | External forwarding set on the mailbox |
| Sent mail | Phishing or payment-fraud emails sent from the account |
| Files | Unusual downloads or sharing activity in SharePoint and OneDrive |
| Apps | New OAuth application consents granted by the user |
| Other users | Anyone else who received the same phishing email or visited the phishing domain |

**Example hunting query: new inbox rules (Sentinel).** This query is **untested**, so verify the table and field names in your own environment.

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
| order by TimeGenerated desc

**Find the source:** locate the phishing email, extract the malicious URL and domain, and identify which other users received or clicked it.

5. Phase 4: Eradicate

- Delete malicious inbox rules and remove external forwarding.
- Remove unauthorized OAuth app consents.
- Block the phishing domain and URL in email and web filtering.
- Remove the phishing email from all recipients' mailboxes.
- Confirm no attacker-registered authentication methods remain.
- Run the same investigation for **every other affected user**.

6. Phase 5: Recover

1. Re-enable the account only after containment and eradication are confirmed.
2. Have the user re-register MFA, ideally with a **phishing-resistant method** (passkey or security key).
3. Monitor the account closely for the next 30 days.
4. Notify affected parties. If fraudulent payment requests or data exposure may have occurred, involve finance, legal, and management, and follow your organization's notification obligations.
5. Communicate with the user clearly and without blame.

7. Phase 6: Lessons learned

Hold a short review within a week of closing the incident.

- What was the root cause, and how did the user's session get stolen?
- How long between compromise and detection? Between detection and containment?
- Did the detections fire? Which ones missed, and why?
- Which hardening controls would have prevented this? (See the [hardening guide](../hardening/aitm-hardening-guide.md).)
- Update detection tuning notes, training material, and this playbook.

**Useful metrics:** time to detect, time to contain, number of accounts affected.

8. Quick-reference checklist

- [ ] Evidence exported and timeline started
- [ ] Account blocked or restricted
- [ ] Sessions and refresh tokens revoked
- [ ] Password reset through a secure channel
- [ ] Unauthorized MFA methods removed
- [ ] Inbox rules and forwarding reviewed and cleaned
- [ ] OAuth consents reviewed
- [ ] Phishing email, URL, and domain blocked and purged
- [ ] Other affected users identified and handled
- [ ] User re-enrolled with phishing-resistant MFA
- [ ] Stakeholders notified as required
- [ ] Lessons-learned review completed

9. MITRE ATT&CK reference

| Technique | Relevance |
| [T1566.002 Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | Initial access |
| [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) | Credential and session interception |
| [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) | Session token theft |
| [T1556.006 Modify Authentication Process: MFA](https://attack.mitre.org/techniques/T1556/006/) | Persistence through added MFA methods |
| [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | Use of the stolen session |

10. Exercise log (to complete)

| Date | Exercise type | Participants | Findings | Playbook updates made |
|------|---------------|--------------|----------|-----------------------|
| | Tabletop | | | |
