"""Map findings to security standards: OWASP Top 10 (2025), CWE, and NIST SSDF.

Each checklist rule lists standard IDs in rules/checklist.yml. enrich() copies
those onto every finding for the rule, merges in any extra IDs the scanner
supplied (e.g. the CWE of a specific CVE), and attaches readable names and
links from the catalog below, so the report can say "CWE-89: SQL Injection"
instead of a bare number.
"""

from __future__ import annotations

from dataclasses import replace

from safecode.rules import Rule
from safecode.schema import Finding, StandardRef

OWASP, CWE, NIST_SSDF = "OWASP", "CWE", "NIST-SSDF"

# checklist.yml mapping keys -> framework names used in StandardRef
FRAMEWORK_KEYS = {"owasp": OWASP, "cwe": CWE, "nist_ssdf": NIST_SSDF}

OWASP_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Names for the CWEs SAFECODE's own rules use, plus ones that commonly appear
# on dependency advisories. Unknown CWEs still get a working link, just no name.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-295": "Improper Certificate Validation",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-538": "Sensitive Information in an Externally-Accessible File",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
    "CWE-1357": "Reliance on Insufficiently Trustworthy Component",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}

# NIST SP 800-218 (Secure Software Development Framework) v1.1 practices.
NIST_SSDF_PRACTICES = {
    "PO.1": "Define Security Requirements for Software Development",
    "PO.2": "Implement Roles and Responsibilities",
    "PO.3": "Implement Supporting Toolchains",
    "PO.4": "Define and Use Criteria for Software Security Checks",
    "PO.5": "Implement and Maintain Secure Environments for Software Development",
    "PS.1": "Protect All Forms of Code from Unauthorized Access and Tampering",
    "PS.2": "Provide a Mechanism for Verifying Software Release Integrity",
    "PS.3": "Archive and Protect Each Software Release",
    "PW.1": "Design Software to Meet Security Requirements and Mitigate Security Risks",
    "PW.2": "Review the Software Design to Verify Compliance with Security Requirements",
    "PW.4": "Reuse Existing, Well-Secured Software When Feasible",
    "PW.5": "Create Source Code by Adhering to Secure Coding Practices",
    "PW.6": "Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security",
    "PW.7": "Review and/or Analyze Human-Readable Code to Identify Vulnerabilities",
    "PW.8": "Test Executable Code to Identify Vulnerabilities",
    "PW.9": "Configure Software to Have Secure Settings by Default",
    "RV.1": "Identify and Confirm Vulnerabilities on an Ongoing Basis",
    "RV.2": "Assess, Prioritize, and Remediate Vulnerabilities",
    "RV.3": "Analyze Vulnerabilities to Identify Their Root Causes",
}

SSDF_URL = "https://csrc.nist.gov/pubs/sp/800/218/final"

# Display order in reports: the most widely recognised framework first.
_FRAMEWORK_ORDER = {OWASP: 0, CWE: 1, NIST_SSDF: 2}


def describe(framework: str, standard_id: str) -> StandardRef:
    """Build a StandardRef with the official name and a link, where known."""
    if framework == OWASP:
        name = OWASP_2025.get(standard_id, "")
        if name:
            number, year = standard_id.split(":")
            url = f"https://owasp.org/Top10/{year}/{number}_{year}-{name.replace(' ', '_')}/"
        else:
            # e.g. an OWASP 2021 ID coming from a third-party Semgrep rule
            url = "https://owasp.org/Top10/"
        return StandardRef(OWASP, standard_id, name, url)
    if framework == CWE:
        number = standard_id.removeprefix("CWE-")
        return StandardRef(CWE, standard_id, CWE_NAMES.get(standard_id, ""),
                           f"https://cwe.mitre.org/data/definitions/{number}.html")
    if framework == NIST_SSDF:
        return StandardRef(NIST_SSDF, standard_id, NIST_SSDF_PRACTICES.get(standard_id, ""), SSDF_URL)
    return StandardRef(framework, standard_id)


def standards_for_rule(rule: Rule) -> tuple[StandardRef, ...]:
    """All standards a checklist rule maps to, with names and links."""
    refs = [
        describe(FRAMEWORK_KEYS[key], standard_id)
        for key, ids in rule.mapping.items()
        for standard_id in ids
    ]
    return _ordered(refs)


def enrich(finding: Finding, rules: dict[str, Rule]) -> Finding:
    """Return a copy of finding with standards, why-it-matters, and fix filled in.

    Values already set on the finding win: a per-finding fix like "Upgrade
    lodash to 4.17.21" is more useful than the rule's generic advice.

    CWEs get one extra step. A rule often lists alternatives (SC-008 covers
    both CWE-319 cleartext HTTP and CWE-295 bad certificates). If a finding
    names a CWE from that list, it gets only its own CWE, not all of them. If
    it names CWEs outside the list (a CVE's specific weakness), they are added
    alongside the rule's.
    """
    rule = rules.get(finding.rule_id)
    rule_refs = list(standards_for_rule(rule)) if rule else []
    own_cwes = {ref.id for ref in finding.standards if ref.framework == CWE}
    rule_cwes = {ref.id for ref in rule_refs if ref.framework == CWE}
    if own_cwes and own_cwes <= rule_cwes:
        rule_refs = [ref for ref in rule_refs if ref.framework != CWE or ref.id in own_cwes]

    refs = rule_refs + [describe(ref.framework, ref.id) for ref in finding.standards]
    return replace(
        finding,
        standards=_ordered(refs),
        why_it_matters=finding.why_it_matters or (rule.why_it_matters if rule else ""),
        fix=finding.fix or (rule.fix if rule else ""),
    )


def cwe_to_rule(rules: dict[str, Rule], check_type: str = "semgrep") -> dict[str, str]:
    """Map each CWE to the first enabled rule of check_type that lists it.

    Used to place findings from third-party Semgrep rules into the checklist.
    """
    mapping: dict[str, str] = {}
    for rule in rules.values():
        if rule.enabled and rule.check_type == check_type:
            for cwe in rule.mapping.get("cwe", ()):
                mapping.setdefault(cwe, rule.id)
    return mapping


def _ordered(refs: list[StandardRef]) -> tuple[StandardRef, ...]:
    """De-duplicate by (framework, id), keeping the first, then sort by framework."""
    unique: dict[tuple[str, str], StandardRef] = {}
    for ref in refs:
        unique.setdefault((ref.framework, ref.id), ref)
    return tuple(sorted(unique.values(), key=lambda r: _FRAMEWORK_ORDER.get(r.framework, 99)))
