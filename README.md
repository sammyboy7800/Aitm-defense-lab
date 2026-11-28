 🛡️ AiTM Defense Lab

> Detecting and preventing Adversary-in-the-Middle (AiTM) phishing attacks

👋 About
Hi, I'm Samson Oragbon, an aspiring IT/security professional. This project
documents my hands-on work understanding, detecting, and mitigating
AiTM phishing, which steals session cookies and can bypass standard MFA.

 🎯 Objectives
- Explain how AiTM attacks bypass traditional MFA
- Build detection queries for suspicious sign-ins and token replay
- Document phishing-resistant defenses (FIDO2/passkeys, Conditional Access)
- Provide an incident response playbook
- Map findings to MITRE ATT&CK

🧰 Tech & Tools
Microsoft Entra ID · KQL · Azure Data Explorer · Microsoft Sentinel · MITRE ATT&CK · Git · Markdown
📁 Repository Structure

| Folder | Contents | Status |
| [`/docs`](docs) | [How AiTM works](docs/how-aitm-works.md) | ✅ Done |
| [`/detections`](detections) | [Session reuse](detections/aitm-session-reuse.md) · [MFA registration after risky sign-in](detections/aitm-mfa-registration-after-risky-signin.md) | ✅ Tested on synthetic data |
| [`/hardening`](hardening) | [Hardening guide](hardening/aitm-hardening-guide.md) | 🟡 Documented, not yet built in a lab tenant |
| [`/incident-response`](incident-response) | [IR playbook](incident-response/aitm-incident-response-playbook.md) | 🟡 Draft, Walked through once in a solo tabletop exercise (see tabletop-exercise-bob.md) |

 🔍 Key Findings
- AiTM steals the **session**, not just the password, which is why standard MFA can be bypassed.
- A KQL rule that flags one session used from multiple IPs and countries correctly caught the replayed session in my synthetic test data and ignored normal and failed sign-ins.
- A second rule that links a risky sign-in to a new MFA registration within an hour catches attacker persistence.
- Detection has limits: an attacker using a proxy in the victim's own country can avoid the session-reuse rule, which is why prevention (phishing-resistant MFA) matters most.
- Token protection helps, but Microsoft documents limits on supported platforms and apps, so it is a layer, not a replacement for passkeys.

 🔗 Related Projects
- [Detection Pipeline Lab 1](https://github.com/sammyboy7800/Detection-Pipeline-lab1):
  Cribl Stream + Splunk pipeline with MITRE ATT&CK-mapped detections for
  SSH brute force and web reconnaissance. This project builds on that
  foundation by applying detection engineering to a modern identity attack.

 📜 Certifications & Learning
- [x] CompTIA Security+
- [x] Microsoft SC-200
- [x] Certified Information Security Manager (CISM)
 📫 Contact
LinkedIn: [linkedin.com/in/soragbon](https://www.linkedin.com/in/soragbon) · Email: orasam07@gmail.com

⚠️ Disclaimer
This project is for defensive and educational purposes only.
Detections were tested on synthetic data only, not against a production environment.
