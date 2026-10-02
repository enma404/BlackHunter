# Ethical Guidelines — BlackHunter

> **Read this document before using any part of BlackHunter.**
> By installing, running, or modifying this toolkit, you agree to the terms below.

---

## 1. Purpose of This Project

BlackHunter is a **security research and education framework** intended for:

- Authorized penetration testing engagements
- Capture-the-Flag (CTF) competitions
- Academic security research
- Personal lab environments you own and control
- Red-team exercises with explicit written authorization

BlackHunter is **not** a tool for unauthorized access, surveillance, harassment, or any activity that violates local, national, or international law.

---

## 2. Legal Compliance

You are solely responsible for complying with all applicable laws, including but not limited to:

- **Computer Fraud and Abuse Act (CFAA)** — United States
- **Computer Misuse Act** — United Kingdom
- **GDPR / Data Protection laws** — European Union
- **Convention on Cybercrime (Budapest Convention)**
- **Local statutes** in your country of residence and the country of the target

Ignorance of the law is **not** a defense. If you are unsure whether an action is legal, **stop and consult a lawyer**.

---

## 3. Authorization Requirement

You may only use BlackHunter against a system if **at least one** of the following is true:

1. **You own the system** (physical or virtual, and you hold the legal right to test it).
2. **You have written, signed authorization** from the system owner that explicitly defines:
   - Scope (IP ranges, domains, applications)
   - Time window of the engagement
   - Permitted techniques (e.g., no DoS, no social engineering)
   - Rules of engagement (RoE) and emergency contacts
3. **You are operating in a sanctioned CTF** where the organizers have granted permission for the specific targets.

A verbal "okay" is **not** sufficient. Always get it in writing.

---

## 4. Prohibited Uses

The following uses are **strictly forbidden**:

- Attacking systems without explicit authorization
- Scanning or exploiting public infrastructure you do not own
- Deploying the C2 server against real victims
- Using payloads or exploits to damage, disrupt, or destroy data
- Exfiltrating, selling, or publishing stolen data
- Bypassing security controls for malicious or financial gain
- Harassment, stalking, or doxxing via collected information
- Any use against critical infrastructure (power, water, healthcare, finance) without government-level authorization
- Any use against individuals' personal devices without their informed consent

Violation of these rules may result in **criminal prosecution**, civil liability, and permanent exclusion from the security community.

---

## 5. Scope Discipline

When operating under an engagement:

- **Stay in scope.** Never scan or exploit IPs/domains outside the agreed list.
- **Respect time windows.** Do not run active tests outside agreed hours.
- **Rate-limit aggressively.** Avoid accidental denial-of-service.
- **Stop on discovery.** If you encounter evidence of a pre-existing compromise or illegal content, stop and notify the client immediately.
- **Do not pivot.** A foothold does not grant permission to move laterally unless explicitly authorized.

---

## 6. Data Handling

- Treat all data collected during an engagement as **confidential**.
- Encrypt findings at rest and in transit.
- Delete client data after the engagement unless contractually required to retain it.
- Never publish, share, or sell client data, screenshots, or credentials.
- Redact sensitive information (PII, credentials, internal IPs) in reports unless the client requests otherwise.

---

## 7. Responsible Disclosure

If you discover a vulnerability in a system you are **not** authorized to test:

1. **Do not exploit it.**
2. Document the finding privately.
3. Contact the vendor/owner through their security contact or a bug bounty program.
4. Allow a reasonable disclosure window (typically 90 days).
5. Coordinate public disclosure only after a fix is available.

---

## 8. Community Standards

- Give credit where it is due. Do not claim others' research as your own.
- Do not use BlackHunter to harass or intimidate other researchers.
- Share knowledge responsibly — publish techniques only after they can be mitigated.
- Mentor newcomers ethically; do not teach attack techniques without teaching the legal and ethical framework around them.

---

## 9. Liability Disclaimer

BlackHunter is provided **"as is"**, without warranty of any kind. The authors and contributors:

- Are **not responsible** for any misuse of this software.
- Are **not liable** for any damage, legal consequence, or data loss resulting from its use.
- Do **not endorse** any unauthorized or illegal activity.

You assume **full responsibility** for your actions.

---

## 10. Acknowledgment

By using BlackHunter, you acknowledge that:

- You have read and understood these guidelines.
- You will use the toolkit only in authorized, lawful contexts.
- You accept full legal and ethical responsibility for your actions.

---

## 11. Reporting Ethical Concerns

If you become aware of misuse of BlackHunter, or if you are unsure whether a planned action is ethical, contact the maintainers at:

> **security@blackhunter.example** *(replace with a real contact before release)*

---

*Last updated: 2026*
*Version: 1.0*