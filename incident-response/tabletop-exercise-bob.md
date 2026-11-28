Tabletop Exercise: Suspected AiTM Compromise of a User Account
| Field | Detail |
| **Playbook tested** | [AiTM Incident Response Playbook](aitm-incident-response-playbook.md) |
| **Exercise date** | 11-20-26 |
| **Format** | Solo walkthrough (discussion-based, no live systems) |
| **Duration** | [129 minutes |
| **Facilitator / analyst** | Samson Oragbon |
| **Scenario data** | Synthetic data from the [MFA registration detection test] (../detections/aitm-mfa-registration-after-risky-signin.md) |

This is a fictional scenario. All users, IP addresses, and events are synthetic.
1. Objective
Is to test whether the playbook gives enough direction to respond to a realistic AiTM compromise, and record the gaps found.
2. Scenario and injects
An "inject" is a new piece of information revealed during the exercise. 
Inject 1: The alert (10:25)
My SIEM raises an alert from the MFA registration detection. User `bob@contoso.test` had a **high-risk successful sign-in at 10:00** from `192.0.2.99`, and a **new MFA method was registered at 10:20** from the same IP.
Inject 2: Context (10:30)
Bob works in the **finance team** and can approve payment requests.

Inject 3: Mailbox review (10:45)
Analyst find a **new inbox rule** created on Bob's mailbox at 10:22 that moves any email containing the word "invoice" to the RSS Subscriptions folder and forwards a copy to an external address.
Inject 4: Wider scope (11:15)
A search of recent sign-ins shows two more users with risky sign-ins: `carol@contoso.test` (medium risk, 11:00) and `dave@contoso.test` (high risk, 12:00 on the previous timeline). Neither has registered a new MFA method.
Inject 5: User contact (11:30)
Analyst reach Bob by phone, and ask him about the time of signing in. He said he clicked a "shared document" link around 09:55 after he signed in. He doesn't recognize the new MFA method.
3. Response log
Phase 1: Detect and triage
| Question | My answer |
| Is this a true positive or a false positive? Why? | it cannot be decided yet because not all fact are verified
| What severity do I assign, and why? | |the severity is high and because bob credential that was stolen has the ability to approve payment which can cause the organization financial loss
| What do I record in the timeline first? | |Bob credential has been compromised and we need to stop and disable his credential from being used by this bad actor (Security breach = stolen credential)
| Playbook steps used | | interview and question response technique
| **Gap or unclear point in the playbook** | | How many people are involved in clicking the shared document linked
### Phase 2: Contain
| Question | My answer |
| What are my first three actions, in order? | |first action is to disable bob account, then disconnect his system from the network and finally isolate the system for further investigation
| How do I decide whether to block the account? | | I will decide once bob confirmed he has click a share link document and I can see that the mailbox is sending any word that contain “invoice” to an external address in his email
| Who do I need to tell right away (user, manager, finance)? | |I will tell all user in the finance unit, to watch out for suspicious shared linked by not to clicking any link from share document until further investigation is completed and they will be notified
| Playbook steps used | |tabletop interview and question response technique
| **Gap or unclear point in the playbook** | | where do the share link document originated from
### Phase 3: Investigate scope
| Question | My answer |
| What logs or tables do I check, and in what order? | |the sign in log, the exchange message trace and email log and audit trail log
| How do I find the phishing email and other recipients? | | From the audit trail and email trace log that captured his originality
| What do I do about Carol and Dave? | |I will verify if Carol and Dave has click on the share document link also
| What evidence might I have lost if I waited? | |The stolen credential of Bob that can be used to cause further damage to the organization
| Playbook steps used | |question and answer response technique
| **Gap or unclear point in the playbook** | | we still do not know how many users has clicked the share link document
### Phase 4: Eradicate
| Question | My answer |
| What do I remove or clean up? | |remove the phishing email by changing bob credential and by ensuring that Authentication is bound to the real website's domain, so it fails on a look-alike proxy page and require a compliant or managed device, block risky sign-ins, and restrict access by location or conditions
| How do I block the phishing domain? | |use security software real time protection if that was not available at that point in time
| Playbook steps used | | interview and answer response technique
| **Gap or unclear point in the playbook** | |we do not know if security software real time protection was installed on the system or not?
### Phase 5: Recover and communicate
| Question | My answer |
| When is it safe to re-enable Bob's account? | |After it has been confirmed that the link has been block and eradicated from the network
| What do I tell Bob? What do I tell finance and management? | | educate him on phishing email technique and ways to identify them, tell finance and management that the situation is resolved and train all involved about phishing email technique and ways of identification
| Could any fraudulent payments have occurred, and who checks? | |verify by asking if any payment has been initiated and approved by Bob, Carol, or Dave, within the time frame and confirm by those who have approval of invoices payment
| Playbook steps used | | interview and answer techniques
| **Gap or unclear point in the playbook** | | Timeframe of calling to find-out from bob and other involved 
### Phase 6: Lessons learned
| Question | My answer |
| Which control would have prevented this? | | Authentication is bound to the real website's domain, so it fails on a look-alike proxy page.
| Did the detections fire as expected? What would have been missed? | |Yes, the aitm attack would have increase and further damages would not have been capture earlier. 
| What would I change in training or hardening? | | I would hardening my network with security software for real time automation and train my staff more on phishing technique observation
## 4. Gap register
List every weakness found in the playbook, then fix it.
| # | Gap found | Severity (low/med/high) | Fix applied to playbook? |
|---|-----------|-------------------------|--------------------------|
| 1 |H | | x | Employee phishing email and security awareness, Train employee about phishing email and security awareness and ensure there is a prize for the best security awareness employee annually or half yearly.
| 2 |H| | x | Ensure organization is using the right tools, ensure organization has the minimum right tool that can detect and alert security team of any new detection in the environment and also ensure it is the industry minimal standard
| 3 |H | | x | Continuous monitoring and improvement on tools and employee, organization should make sure their tools are always monitored and upgraded to the industry minimum standard and also by ensuring all vulnerability are managed according to company risk policy. While employee need continuous training to stay abreast with technological advancement
## 5. Summary
**What worked well: The siem gave notification and the security analyst acted on time to figure the situation out
**What needs improvement:** Ensure real-time security automation need to be in the environment and employee need to be trained on phishing and security awareness 
**Playbook changes made as a result:** This will increase the security awareness of the employee and the network protection of the organization
*Disclaimer: Fictional scenario for defensive training and educational purposes only.*
