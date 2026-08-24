"""Bundled CWE dictionary.

Maps common CWE identifiers to a short name, a one-line description, and the
attack patterns (CAPEC) typically associated with them. This is a curated
subset covering the CWEs that appear most frequently on CVEs — unknown CWEs
fall back to just the ID with a link to cwe.mitre.org.
"""

# CWE-<id> : {"name", "desc", "capec": [ "CAPEC-<id>: <name>", ... ]}
CWE_DB: dict[str, dict] = {
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "desc": "Improper neutralization of input during web page generation, letting attackers inject scripts into pages viewed by others.",
        "capec": ["CAPEC-63: Cross-Site Scripting", "CAPEC-591: Reflected XSS", "CAPEC-592: Stored XSS"],
    },
    "CWE-89": {
        "name": "SQL Injection",
        "desc": "Improper neutralization of special elements in SQL commands, allowing manipulation of database queries.",
        "capec": ["CAPEC-66: SQL Injection", "CAPEC-7: Blind SQL Injection"],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "desc": "Improper neutralization of special elements used in an OS command, allowing arbitrary command execution.",
        "capec": ["CAPEC-88: OS Command Injection"],
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "desc": "Product does not validate or incorrectly validates input, affecting control flow or data handling.",
        "capec": ["CAPEC-153: Input Data Manipulation"],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "desc": "Improper limitation of a pathname to a restricted directory ('../'), allowing access to unintended files.",
        "capec": ["CAPEC-126: Path Traversal"],
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "desc": "Web app does not verify that a request was intentionally sent by the user.",
        "capec": ["CAPEC-62: Cross Site Request Forgery"],
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "desc": "Product allows upload of dangerous file types that can be executed on the server.",
        "capec": ["CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs"],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "desc": "Deserializing attacker-controlled data can lead to code execution or object injection.",
        "capec": ["CAPEC-586: Object Injection"],
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "desc": "Improper restriction of XML external entity references, enabling file disclosure or SSRF.",
        "capec": ["CAPEC-201: XML External Entities Blowup"],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "desc": "Web server can be induced to make requests to unintended destinations.",
        "capec": ["CAPEC-664: Server Side Request Forgery"],
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "desc": "Writing past the end or before the beginning of a buffer, causing corruption or code execution.",
        "capec": ["CAPEC-100: Overflow Buffers"],
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "desc": "Reading data past the end or before the beginning of a buffer, leaking memory contents.",
        "capec": ["CAPEC-540: Overread Buffers"],
    },
    "CWE-416": {
        "name": "Use After Free",
        "desc": "Referencing memory after it has been freed, leading to crashes or code execution.",
        "capec": ["CAPEC-100: Overflow Buffers"],
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "desc": "Dereferencing a NULL pointer, typically causing a crash / denial of service.",
        "capec": [],
    },
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "desc": "An integer calculation overflows, producing an unexpected small value used elsewhere.",
        "capec": ["CAPEC-92: Forced Integer Overflow"],
    },
    "CWE-119": {
        "name": "Improper Restriction of Memory Buffer Operations",
        "desc": "Operations on a memory buffer can read from or write outside its bounds.",
        "capec": ["CAPEC-100: Overflow Buffers"],
    },
    "CWE-120": {
        "name": "Buffer Copy without Size Check (Classic Buffer Overflow)",
        "desc": "Copying input to a buffer without checking size, overflowing it.",
        "capec": ["CAPEC-100: Overflow Buffers"],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "desc": "Product does not correctly prove or restrict a claimed identity.",
        "capec": ["CAPEC-114: Authentication Abuse"],
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "desc": "A critical function does not require authentication.",
        "capec": ["CAPEC-12: Choosing Message/Channel Identifier on Behalf of Party"],
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "desc": "Product does not perform an authorization check before granting access.",
        "capec": ["CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs"],
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "desc": "Product performs an authorization check but does so incorrectly.",
        "capec": [],
    },
    "CWE-269": {
        "name": "Improper Privilege Management",
        "desc": "Product does not properly assign, track, or drop privileges.",
        "capec": ["CAPEC-122: Privilege Abuse"],
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "desc": "Product exposes sensitive information to an actor not authorized to see it.",
        "capec": ["CAPEC-116: Excavation"],
    },
    "CWE-732": {
        "name": "Incorrect Permission Assignment for Critical Resource",
        "desc": "A critical resource is assigned permissions that allow unintended access.",
        "capec": ["CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs"],
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "desc": "Product contains hard-coded credentials for authentication or encryption.",
        "capec": ["CAPEC-191: Read Sensitive Constants Within an Executable"],
    },
    "CWE-77": {
        "name": "Command Injection",
        "desc": "Improper neutralization of special elements used in a command.",
        "capec": ["CAPEC-248: Command Injection"],
    },
    "CWE-94": {
        "name": "Code Injection",
        "desc": "Product constructs code from input without neutralization, allowing execution.",
        "capec": ["CAPEC-242: Code Injection"],
    },
    "CWE-259": {
        "name": "Use of Hard-coded Password",
        "desc": "Product uses a hard-coded password for its own authentication.",
        "capec": ["CAPEC-70: Try Common or Default Usernames and Passwords"],
    },
    "CWE-276": {
        "name": "Incorrect Default Permissions",
        "desc": "Product installs with insecure default permissions.",
        "capec": [],
    },
    "CWE-284": {
        "name": "Improper Access Control",
        "desc": "Product does not restrict or incorrectly restricts access to a resource.",
        "capec": ["CAPEC-58: Restful Privilege Elevation"],
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "desc": "Product does not control allocation/maintenance of a limited resource (DoS).",
        "capec": ["CAPEC-125: Flooding"],
    },
    "CWE-401": {
        "name": "Missing Release of Memory (Memory Leak)",
        "desc": "Product does not release memory after use, leading to exhaustion.",
        "capec": [],
    },
    "CWE-522": {
        "name": "Insufficiently Protected Credentials",
        "desc": "Product transmits or stores credentials with insufficient protection.",
        "capec": ["CAPEC-102: Session Sidejacking"],
    },
    "CWE-601": {
        "name": "Open Redirect",
        "desc": "URL redirection to untrusted site, aiding phishing.",
        "capec": ["CAPEC-178: Cross-Site Flashing"],
    },
    "CWE-770": {
        "name": "Allocation of Resources Without Limits",
        "desc": "Product allocates resources without limits or throttling (DoS).",
        "capec": ["CAPEC-125: Flooding"],
    },
    "CWE-347": {
        "name": "Improper Verification of Cryptographic Signature",
        "desc": "Product does not verify, or incorrectly verifies, a cryptographic signature.",
        "capec": ["CAPEC-463: Padding Oracle Crypto Attack"],
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "desc": "Product does not validate, or incorrectly validates, a certificate.",
        "capec": ["CAPEC-459: Creating a Rogue Certification Authority Certificate"],
    },
    "CWE-1236": {
        "name": "Formula Injection (CSV Injection)",
        "desc": "Improper neutralization of formula elements in a CSV file.",
        "capec": [],
    },
    "CWE-74": {
        "name": "Injection",
        "desc": "Improper neutralization of special elements in output used by a downstream component.",
        "capec": ["CAPEC-152: Inject Unexpected Items"],
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "desc": "Product stores sensitive information in cleartext.",
        "capec": ["CAPEC-37: Retrieve Embedded Sensitive Data"],
    },
    "CWE-319": {
        "name": "Cleartext Transmission of Sensitive Information",
        "desc": "Product transmits sensitive data in cleartext over a network.",
        "capec": ["CAPEC-157: Sniffing Attacks"],
    },
    "CWE-1333": {
        "name": "Inefficient Regular Expression Complexity (ReDoS)",
        "desc": "A regex allows attacker input to trigger catastrophic backtracking (DoS).",
        "capec": ["CAPEC-492: Regular Expression Exponential Blowup"],
    },
    "CWE-668": {
        "name": "Exposure of Resource to Wrong Sphere",
        "desc": "Product exposes a resource to an unintended control sphere.",
        "capec": [],
    },
    "CWE-427": {
        "name": "Uncontrolled Search Path Element (DLL Hijacking)",
        "desc": "Product uses a search path that can be controlled by an attacker.",
        "capec": ["CAPEC-471: Search Order Hijacking"],
    },
    "CWE-59": {
        "name": "Link Following",
        "desc": "Product does not properly handle symbolic or hard links.",
        "capec": ["CAPEC-132: Symlink Attack"],
    },
}


def lookup_cwe(cwe_id: str) -> dict:
    """Return {id, name, desc, capec, url} for a CWE identifier.

    Falls back to just the id + MITRE URL when the CWE isn't in the bundle.
    """
    cwe_id = (cwe_id or "").strip().upper()
    num = cwe_id.split("-")[1] if "-" in cwe_id else ""
    url = f"https://cwe.mitre.org/data/definitions/{num}.html" if num.isdigit() else ""
    entry = CWE_DB.get(cwe_id)
    if entry:
        return {
            "id": cwe_id,
            "name": entry["name"],
            "desc": entry["desc"],
            "capec": entry.get("capec", []),
            "url": url,
        }
    return {"id": cwe_id, "name": "", "desc": "", "capec": [], "url": url}
