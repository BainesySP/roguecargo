# RogueCargo CLI - Payload Suggester

## 🔥 Overview
RogueCargo is a command-line tool designed to suggest and encode various security payloads. It provides SQL Injection, XSS, LFI, Command Injection, and other payloads, allowing users to choose encoding options such as Base64, URL encoding, and Hex.

## 🚀 Features
- Supports multiple payload types: **SQL Injection, XSS, LFI, XXE, SSRF, Command Injection, LDAP Injection, Shell, Web Shells**.
- Encoding options: **None, Base64, URL Encoding, Hex**.
- OS-specific payloads for **Windows** and **Linux**.
- Interactive CLI with a custom prompt (`RogueCargo-[~]`).

## 🔧 Usage
Run the script with:
```sh
python roguecargo.py
```
Then follow the interactive prompts:
1. Select the payload type.
2. If applicable, select the target operating system (Linux/Windows).
3. Choose an encoding method.
4. View and copy the encoded payload.

## 🎯 Example Usage
```sh
python roguecargo.py
```
**Example Output:**
```
🔥 Welcome to RogueCargo - Your Payload Generator 🔥
Enter attacker IP (for reverse shells, etc.): 192.168.1.100

What type of payload do you need?
[1] SQL Injection
[2] XSS
[3] LFI
...
RogueCargo-[~] 3

What is the target operating system?
[1] Linux
[2] Windows
RogueCargo-[~] 1

Choose an encoding technique:
[1] None
[2] URL Encoding
[3] Base64
RogueCargo-[~] 2

[+] Encoded Payloads:
  - %2Fetc%2Fpasswd
  - %2Fproc%2Fself%2Fenviron
```

## 📌 Supported Payloads
- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Local File Inclusion (LFI)**
- **XXE Injection**
- **Server-Side Request Forgery (SSRF)**
- **LDAP Injection**
- **Command Injection**
- **Server-Side Template Injection (SSTI)**
- **Reverse Shells**
- **Web Shells**

## 🛡 Disclaimer
This tool is intended for research and educational purposes **only**. Use it responsibly and only on systems where you have explicit permission.

## 📜 License
MIT License. See `LICENSE` for details.

## 🤝 Contributing
Pull requests are welcome! If you have ideas for additional payloads or encodings, submit an issue or PR.

## 📞 Support
For any issues or suggestions, open a GitHub issue or contact the maintainer.

---
**Happy Hacking! 🔥**

