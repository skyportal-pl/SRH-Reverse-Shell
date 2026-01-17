# MicrosoftNetworkingServices – Totally-Not-Suspicious Reverse Shell (C)

![Language](https://img.shields.io/badge/language-C-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Build](https://img.shields.io/badge/build-MSVC-success)
![License](https://img.shields.io/badge/license-Absolutely_Not_OK-red)
![Stability](https://img.shields.io/badge/stability-Unhinged-black)
![Stealth](https://img.shields.io/badge/stealth-Questionable-yellow)

---

## 🔥 Overview

This delightful abomination is a **Windows reverse shell implemented in pure C**, crafted with the elegance of a drunk raccoon smashing a keyboard.  
It masquerades as "Microsoft Networking Services" because subtlety is for cowards.

The program:

- copies itself into `%AppData%` under a very "legit" folder
- adds itself to startup through the registry
- spawns a hidden `cmd.exe`
- redirects input/output over a TCP socket
- tries really hard to look official while behaving like a gremlin

This software is for **educational analysis only**.  
If you use it maliciously, you deserve whatever digital curb-stomp life gives you.

---
