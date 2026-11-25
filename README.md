# 🛡️ AiTM Defense Lab

Detecting and preventing Adversary-in-the-Middle (AiTM) phishing attacks
About 

Hi, I am Samson Oragbon, an aspiring IT/security professional. This project
documents my hands-on work understanding, detecting, and mitigating
AiTM phishing, which steals session cookies and can bypass standard MFA.

Objectives
- Explain how AiTM attacks bypass traditional MFA
- Build detection queries for suspicious sign-ins and token replay
- Document phishing-resistant defenses (FIDO2/passkeys, Conditional Access)
- Map findings to MITRE ATT&CK

Tech & Tools
Microsoft Entra ID · KQL · Microsoft Sentinel · MITRE ATT&CK · Git · Markdown

📁 Repository Structure
| Folder | Contents | Status |
| [`/docs`](docs) | [How AiTM works](docs/how-aitm-works.md) | ✅ Done |
| [`/detections`](detections) | [Session reuse detection](detections/aitm-session-reuse.md) | 🟡 Draft, testing next |
| `/hardening` | Conditional Access and FIDO2 guides | ⏳ Planned |
| `/incident-response` | Response playbook | ⏳ Planned |

🔗 Related Projects
- [Detection Pipeline Lab 1](https://github.com/sammyboy7800/Detection-Pipeline-lab1):
  Cribl Stream + Splunk pipeline with MITRE ATT&CK-mapped detections for
  SSH brute force and web reconnaissance. This project builds on that
  foundation by applying detection engineering to a modern identity attack.

📜 Certifications & Learning
 CompTIA Security+
 Microsoft SC-200
 Certified Information Security Manager

📫 Contact
LinkedIn: www.linkedin.com/in/soragbon · Email: orasam07@gmail.com

This project is for defensive and educational purposes only.
