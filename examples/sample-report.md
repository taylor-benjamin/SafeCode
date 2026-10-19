## 🛡️ SAFECODE security report for `vulnerable-app`

### 🔴 Grade F · 0/100

<sub>Based on 7 of 8 checks; 1 could not run (see the checklist below).</sub>

**22 findings**: 🔴 3 critical · 🟠 11 high · 🟡 7 medium · 🔵 1 low · ⚪ 0 info

<details>
<summary>How this score was calculated</summary>

| Rule | Findings | Points |
|---|---|---|
| **SC-002** No known-vulnerable dependencies | 8 | −40 (capped from −104) |
| **SC-003** No SQL injection or unsafe eval | 6 | −40 (capped from −60) |
| **SC-001** No secrets in code or git history | 1 | −25 |
| **SC-008** No cleartext HTTP or disabled TLS verification | 4 | −16 |
| **SC-004** Lockfile present and dependency versions pinned | 1 | −4 |
| **SC-005** .gitignore excludes secrets and credentials | 1 | −4 |
| **SC-006** SECURITY.md exists | 1 | −1 |
| **Total** | | −130 → **0/100** |

Each finding deducts points by severity (critical 25, high 10, medium 4, low 1). Each rule deducts at most 40. A critical finding limits the grade to C. Skipped checks deduct nothing.

</details>

### Checklist

| | Rule | Result | Standards |
|---|---|---|---|
| ❌ | **SC-001** No secrets in code or git history | 1 finding | A07:2025 · CWE-798 · SSDF PS.1 |
| ❌ | **SC-002** No known-vulnerable dependencies | 8 findings | A03:2025 · CWE-1395 · SSDF PW.4 |
| ❌ | **SC-003** No SQL injection or unsafe eval | 6 findings | A05:2025 · CWE-89 · CWE-95 · SSDF PW.5 |
| ❌ | **SC-004** Lockfile present and dependency versions pinned | 1 finding | A03:2025 · CWE-1357 · SSDF PW.4 |
| ❌ | **SC-005** .gitignore excludes secrets and credentials | 1 finding | A02:2025 · CWE-538 · SSDF PS.1 |
| ❌ | **SC-006** SECURITY.md exists | 1 finding | SSDF RV.1 |
| ⏭️ | **SC-007** Branch protection enabled on the default branch | not checked: no GitHub repository (runs automatically in Actions) | A08:2025 · SSDF PS.1 · SSDF PO.5 |
| ❌ | **SC-008** No cleartext HTTP or disabled TLS verification | 4 findings | A04:2025 · CWE-319 · CWE-295 · SSDF PW.5 |

### Findings

#### 🔴 Critical (3)

**Possible secret (generic-api-key)**
`app.py:12` · SC-001 · [OWASP A07:2025](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/ "Authentication Failures") · [CWE-798](https://cwe.mitre.org/data/definitions/798.html "Use of Hard-coded Credentials") · [SSDF PS.1](https://csrc.nist.gov/pubs/sp/800/218/final "Protect All Forms of Code from Unauthorized Access and Tampering")

> A value that looks like a generic api key is written directly in this file.

- **Why it matters:** Anyone who can read the repo (or ever cloned it) can copy a committed key and use it as you. Deleting the file later does not help, because git keeps the old version in history.
- **Fix:** Revoke and rotate the credential first, since it must be treated as leaked. Then move it to an environment variable or your platform's secret store (e.g. GitHub Actions secrets) and, if needed, rewrite history with git filter-repo.

**minimist 1.2.0 has 2 known vulnerabilities**
`package-lock.json:12` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html "Prototype Pollution") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> minimist 1.2.0 (npm) is affected by CVE-2021-44906 (Prototype Pollution in minimist); CVE-2020-7598 (Prototype Pollution in minimist).

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade minimist to 1.2.6 or later.
- **Learn more:** <https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h>, <https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m>

**pyyaml 5.3 has 2 known vulnerabilities**
`requirements.txt:3` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-20](https://cwe.mitre.org/data/definitions/20.html "Improper Input Validation") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> pyyaml 5.3 (PyPI) is affected by CVE-2020-14343 (Improper Input Validation in PyYAML); CVE-2020-1747 (Improper Input Validation in PyYAML).

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade pyyaml to 5.4 or later.
- **Learn more:** <https://osv.dev/vulnerability/PYSEC-2021-142>, <https://osv.dev/vulnerability/PYSEC-2020-96>

#### 🟠 High (11)

**SQL query built from strings**
`app.py:20` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/ "Injection") · [CWE-89](https://cwe.mitre.org/data/definitions/89.html "SQL Injection") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> This SQL query is built by inserting values directly into the query text. Pass values separately, e.g. cursor.execute("... WHERE id = ?", (user\_id,)).

- **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
- **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder. Replace eval with a safe parser such as json.loads or ast.literal\_eval.

**SQL query built from strings**
`app.py:25` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/ "Injection") · [CWE-89](https://cwe.mitre.org/data/definitions/89.html "SQL Injection") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> This SQL query is built by inserting values directly into the query text. Pass values separately, e.g. cursor.execute("... WHERE id = ?", (user\_id,)).

- **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
- **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder. Replace eval with a safe parser such as json.loads or ast.literal\_eval.

**Code evaluated from dynamic input**
`app.py:31` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/ "Injection") · [CWE-95](https://cwe.mitre.org/data/definitions/95.html "Eval Injection") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> eval()/exec() runs whatever text it is given as Python code. If any part of that text comes from a user, they can run code on your server. Use json.loads or ast.literal\_eval to parse data instead.

- **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
- **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder. Replace eval with a safe parser such as json.loads or ast.literal\_eval.

**lodash 4.17.15 has 6 known vulnerabilities**
`package-lock.json:11` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html "Prototype Pollution") · [CWE-770](https://cwe.mitre.org/data/definitions/770.html "Allocation of Resources Without Limits or Throttling") · [CWE-77](https://cwe.mitre.org/data/definitions/77.html "Command Injection") · [CWE-94](https://cwe.mitre.org/data/definitions/94.html "Code Injection") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> lodash 4.17.15 (npm) is affected by CVE-2020-8203 (Prototype Pollution in lodash); CVE-2021-23337 (Command Injection in lodash); CVE-2026-4800 (lodash vulnerable to Code Injection via `_.template` imports key names); and 3 more.

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade lodash to 4.18.0 or later.
- **Learn more:** <https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw>, <https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm>, <https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc>

**idna 2.7.0 has 2 known vulnerabilities**
`requirements.txt` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html "Inefficient Regular Expression Complexity (ReDoS)") · [CWE-400](https://cwe.mitre.org/data/definitions/400.html "Uncontrolled Resource Consumption") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> idna 2.7.0 (PyPI) is affected by CVE-2024-3651 (Internationalized Domain Names in Applications (IDNA) vulnerable to denial of service from specially crafted inputs to idna.encode); CVE-2026-45409 (Internationalized Domain Names in Applications (IDNA): Specially crafted inputs to idna.encode() can bypass CVE-2024-3651 fix).

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade idna to 3.15 or later.
- **Learn more:** <https://osv.dev/vulnerability/PYSEC-2024-60>, <https://osv.dev/vulnerability/PYSEC-2026-215>

**urllib3 1.23.0 has 12 known vulnerabilities**
`requirements.txt` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-295](https://cwe.mitre.org/data/definitions/295.html "Improper Certificate Validation") · [CWE-200](https://cwe.mitre.org/data/definitions/200.html "Exposure of Sensitive Information") · [CWE-409](https://cwe.mitre.org/data/definitions/409.html) · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> urllib3 1.23.0 (PyPI) is affected by CVE-2019-11324 (Improper Certificate Validation in urllib3); CVE-2023-43804 (`Cookie` HTTP header isn't stripped on cross-origin redirects); CVE-2025-66471 (urllib3 streaming API improperly handles highly compressed data); and 9 more.

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade urllib3 to 2.8.0 or later.
- **Learn more:** <https://osv.dev/vulnerability/PYSEC-2019-133>, <https://osv.dev/vulnerability/PYSEC-2023-192>, <https://osv.dev/vulnerability/PYSEC-2026-1994>

**requests 2.19.0 has 5 known vulnerabilities**
`requirements.txt:2` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-522](https://cwe.mitre.org/data/definitions/522.html) · [CWE-200](https://cwe.mitre.org/data/definitions/200.html "Exposure of Sensitive Information") · [CWE-670](https://cwe.mitre.org/data/definitions/670.html) · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> requests 2.19.0 (PyPI) is affected by CVE-2018-18074 (Insufficiently Protected Credentials in Requests); CVE-2023-32681 (Unintended leak of Proxy-Authorization header in requests); CVE-2024-35195 (Requests `Session` object does not verify requests after making first request with verify=False); and 2 more.

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade requests to 2.33.0 or later.
- **Learn more:** <https://osv.dev/vulnerability/PYSEC-2018-28>, <https://osv.dev/vulnerability/PYSEC-2023-74>, <https://osv.dev/vulnerability/PYSEC-2026-1873>

**jinja2 2.10 has 6 known vulnerabilities**
`requirements.txt:4` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-693](https://cwe.mitre.org/data/definitions/693.html) · [CWE-400](https://cwe.mitre.org/data/definitions/400.html "Uncontrolled Resource Consumption") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> jinja2 2.10 (PyPI) is affected by CVE-2019-10906 (Jinja2 sandbox escape via string formatting); CVE-2024-56326 (Jinja has a sandbox breakout through indirect reference to format method); CVE-2020-28493 (Regular Expression Denial of Service (ReDoS) in Jinja2); and 3 more.

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade jinja2 to 3.1.6 or later.
- **Learn more:** <https://osv.dev/vulnerability/PYSEC-2019-217>, <https://osv.dev/vulnerability/PYSEC-2026-1475>, <https://osv.dev/vulnerability/PYSEC-2021-66>

**SQL query built from strings**
`server.js:14` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/ "Injection") · [CWE-89](https://cwe.mitre.org/data/definitions/89.html "SQL Injection") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> This SQL query is built by inserting values directly into the query text. Use placeholders instead, e.g. db.query("... WHERE id = ?", \[id\]).

- **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
- **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder. Replace eval with a safe parser such as json.loads or ast.literal\_eval.

**SQL query built from strings**
`server.js:19` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/ "Injection") · [CWE-89](https://cwe.mitre.org/data/definitions/89.html "SQL Injection") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> This SQL query is built by inserting values directly into the query text. Use placeholders instead, e.g. db.query("... WHERE id = ?", \[id\]).

- **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
- **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder. Replace eval with a safe parser such as json.loads or ast.literal\_eval.

**Code evaluated from dynamic input**
`server.js:24` · SC-003 · [OWASP A05:2025](https://owasp.org/Top10/2025/A05_2025-Injection/ "Injection") · [CWE-95](https://cwe.mitre.org/data/definitions/95.html "Eval Injection") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> eval()/new Function() runs whatever text it is given as JavaScript. If any part of it comes from a request, an attacker can run code in your app. Parse data with JSON.parse instead.

- **Why it matters:** If user input becomes part of a query or of code that gets executed, an attacker can type commands instead of data: reading every row in your database, deleting it, or running code on your server.
- **Fix:** Use parameterised queries (placeholders like ? or %s with a separate argument list) or your ORM's query builder. Replace eval with a safe parser such as json.loads or ast.literal\_eval.

<details>
<summary><b>🟡 Medium (7)</b></summary>

**No .gitignore file**
repository-wide · SC-005 · [OWASP A02:2025](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/ "Security Misconfiguration") · [CWE-538](https://cwe.mitre.org/data/definitions/538.html "Sensitive Information in an Externally-Accessible File") · [SSDF PS.1](https://csrc.nist.gov/pubs/sp/800/218/final "Protect All Forms of Code from Unauthorized Access and Tampering")

> The repository has no .gitignore, so nothing stops secret files from being committed by accident.

- **Why it matters:** A single "git add ." can publish your local .env file or a private key. Ignoring these files up front makes that mistake much harder to make.
- **Fix:** Create a .gitignore containing at least: .env, \*.pem, \*.key, credentials\*.

**Cleartext http:// URL**
`app.py:15` · SC-008 · [OWASP A04:2025](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/ "Cryptographic Failures") · [CWE-319](https://cwe.mitre.org/data/definitions/319.html "Cleartext Transmission of Sensitive Information") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> This URL uses plain http://, so anything sent to it (including tokens) can be read or changed on the network. Use https:// instead.

- **Why it matters:** Plain HTTP, or HTTPS without certificate checks, lets anyone on the same network (public Wi-Fi, a compromised router) read or change the data in transit, including passwords and tokens.
- **Fix:** Use https:// URLs and leave certificate verification on (remove verify=False / rejectUnauthorized: false). For self-signed internal certificates, point the client at your CA bundle instead.

**TLS certificate verification disabled**
`app.py:36` · SC-008 · [OWASP A04:2025](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/ "Cryptographic Failures") · [CWE-295](https://cwe.mitre.org/data/definitions/295.html "Improper Certificate Validation") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> TLS certificate verification is turned off, so this connection would accept an attacker's fake certificate. Remove verify=False (or point verify at your CA bundle for internal certificates).

- **Why it matters:** Plain HTTP, or HTTPS without certificate checks, lets anyone on the same network (public Wi-Fi, a compromised router) read or change the data in transit, including passwords and tokens.
- **Fix:** Use https:// URLs and leave certificate verification on (remove verify=False / rejectUnauthorized: false). For self-signed internal certificates, point the client at your CA bundle instead.

**pygments 2.9.0 has 2 known vulnerabilities**
`requirements-dev.txt` · SC-002 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html "Dependency on Vulnerable Third-Party Component") · [CWE-434](https://cwe.mitre.org/data/definitions/434.html) · [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html "Inefficient Regular Expression Complexity (ReDoS)") · [CWE-400](https://cwe.mitre.org/data/definitions/400.html "Uncontrolled Resource Consumption") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> pygments 2.9.0 (PyPI) is affected by CVE-2022-40896 (Pygments vulnerable to ReDoS); CVE-2026-4539 (Pygments has Regular Expression Denial of Service (ReDoS) due to Inefficient Regex for GUID Matching).

- **Why it matters:** Attackers scan the internet for apps running library versions with public exploits. A vulnerable dependency is a vulnerability in your app, even though you did not write that code.
- **Fix:** Upgrade pygments to 2.20.0 or later.
- **Learn more:** <https://osv.dev/vulnerability/PYSEC-2023-117>, <https://osv.dev/vulnerability/PYSEC-2026-2987>

**Unpinned dependencies in requirements-dev.txt**
`requirements-dev.txt:2` · SC-004 · [OWASP A03:2025](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ "Software Supply Chain Failures") · [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html "Reliance on Insufficiently Trustworthy Component") · [SSDF PW.4](https://csrc.nist.gov/pubs/sp/800/218/final "Reuse Existing, Well-Secured Software When Feasible")

> 3 package(s) are not pinned to an exact version: pytest, black, flake8.

- **Why it matters:** Without pinned versions, a build next week can silently pull in a newer package, including a compromised one, that nobody reviewed.
- **Fix:** Pin every package to an exact version with == (for example requests==2.32.3), or generate the file with `pip-compile` / `uv pip compile`.

**Cleartext http:// URL**
`server.js:10` · SC-008 · [OWASP A04:2025](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/ "Cryptographic Failures") · [CWE-319](https://cwe.mitre.org/data/definitions/319.html "Cleartext Transmission of Sensitive Information") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> This URL uses plain http://, so anything sent to it (including tokens) can be read or changed on the network. Use https:// instead.

- **Why it matters:** Plain HTTP, or HTTPS without certificate checks, lets anyone on the same network (public Wi-Fi, a compromised router) read or change the data in transit, including passwords and tokens.
- **Fix:** Use https:// URLs and leave certificate verification on (remove verify=False / rejectUnauthorized: false). For self-signed internal certificates, point the client at your CA bundle instead.

**TLS certificate verification disabled**
`server.js:28` · SC-008 · [OWASP A04:2025](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/ "Cryptographic Failures") · [CWE-295](https://cwe.mitre.org/data/definitions/295.html "Improper Certificate Validation") · [SSDF PW.5](https://csrc.nist.gov/pubs/sp/800/218/final "Create Source Code by Adhering to Secure Coding Practices")

> TLS certificate verification is turned off, so this connection would accept an attacker's fake certificate. Remove rejectUnauthorized: false (or pass your internal CA via the `ca` option).

- **Why it matters:** Plain HTTP, or HTTPS without certificate checks, lets anyone on the same network (public Wi-Fi, a compromised router) read or change the data in transit, including passwords and tokens.
- **Fix:** Use https:// URLs and leave certificate verification on (remove verify=False / rejectUnauthorized: false). For self-signed internal certificates, point the client at your CA bundle instead.

</details>

<details>
<summary><b>🔵 Low (1)</b></summary>

**Missing SECURITY.md**
repository-wide · SC-006 · [SSDF RV.1](https://csrc.nist.gov/pubs/sp/800/218/final "Identify and Confirm Vulnerabilities on an Ongoing Basis")

> None of these files exist: SECURITY.md or .github/SECURITY.md or docs/SECURITY.md.

- **Why it matters:** Without clear instructions, someone who finds a security bug may open a public issue, which tells attackers about it before you can fix it.
- **Fix:** Add a SECURITY.md that names a private contact (an email address or GitHub's private vulnerability reporting) and which versions you support.

</details>

<details>
<summary>Scanners</summary>

| Scanner | Version | Status | Time | Details |
|---|---|---|---|---|
| gitleaks | 8.30.1 | ✅ ran | 0.3s |  |
| osv-scanner | 2.6.0 | ✅ ran | 2.6s |  |
| semgrep | 1.179.0 | ✅ ran | 2.8s |  |

</details>

**Notes**

- ℹ️ Not a git repository, so only current files were checked for secrets (no history).

<sub>Generated by SAFECODE 0.1.0. Findings map to OWASP Top 10 2025, CWE, and NIST SSDF (SP 800-218).</sub>
