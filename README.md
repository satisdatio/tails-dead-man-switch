#  TailsOS Dead Man Switch

> **A sophisticated, auditable, and minimal Dead Man Switch for TailsOS.**  
> Combines air-gap compatibility, tamper-evident logging, and a pixel-perfect native UI.

![Python 3](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![TailsOS](https://img.shields.io/badge/TailsOS-563D7C?logo=linux&logoColor=white)
![GTK3](https://img.shields.io/badge/UI-GTK3-6E92B3?logo=gtk&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Beta-orange)

---

##  Critical Disclaimer

**This tool is for security research and personal protection purposes only.**

- **TailsOS is Amnesic:** This tool **requires Encrypted Persistent Storage**. If persistence is not unlocked, the switch cannot arm, trigger, or survive reboots.
- **No Guarantees:** Use at your own risk. Test thoroughly with non-critical data before deployment.
- **Air-Gap Limitations:** In air-gap mode, network actions (emails) are exported as encrypted drafts for manual transfer. The tool cannot bypass physical isolation.
- **Coercion:** Tails wipes RAM on shutdown. If the system is powered off, the switch stops. This protects against seizure during uptime or failure to check in.
- **Legal Responsibility:** You are responsible for ensuring compliance with applicable laws in your jurisdiction.

---

##  Features

- ** Auditable and Tamper-Evident:**  
  Every action, heartbeat, and configuration change is logged with chained SHA-256 hashes. Any modification to the log breaks the chain, making tampering immediately detectable.

- ** Modern Native UI:**  
  Built with PyGObject (GTK3) for a lightweight, pixel-perfect interface that matches the refined aesthetic of TailsOS without web dependencies. Apple-inspired design language.

- ** Tor & Air-Gap Modes:**  
  - **Tor Mode:** For online Tails sessions with Tor connectivity.  
  - **Air-Gap Mode:** Generates GPG-encrypted payloads for manual export via removable media.

- ** Minimal & Dependency-Free:**  
  Pure Python 3 with standard libraries only. No `pip`, no external packages. Fully auditable codebase under 500 lines.

- ** Flexible Actions:**  
  - Secure file deletion using `shred`
  - Arbitrary command execution
  - Encrypted email draft generation
  - Extensible JSON-based configuration

- ** Integrity Verification:**  
  Built-in audit log verification to detect any tampering attempts.

---

##  Prerequisites

| Requirement | Details |
|-------------|---------|
| **TailsOS** | Version 5.0 or later |
| **Persistent Storage** | Encrypted, with `Personal Data` or `Dotfiles` enabled |
| **Python 3** | Included by default in Tails |
| **GTK3** | Included by default in Tails |
| **GPG** | Included by default for encryption operations |

---

##  Installation

### 1. Create Project Directory

```bash
mkdir -p ~/Persistent/TailsDeadManSwitch
cd ~/Persistent/TailsDeadManSwitch
```

### 2. Clone Repository

```bash
git clone https://github.com/<your-user>/Tails-Dead-Man-Switch .
```

### 3. Set Permissions

```bash
chmod +x dms.py
```

### 4. Initialize Configuration

```bash
./dms.py --init
```

- Follow on-screen prompts to create the first profile.
- Choose action type (file shred, command, encrypted draft) and heartbeat interval.

---

##  Usage

### Start the UI

```bash
./dms.py --gui
```

### Start in headless mode (recommended for scripting)

```bash
./dms.py --run
```

### Verify audit integrity

```bash
./dms.py --verify
```

### Export air-gap payload

```bash
./dms.py --export --path ~/Persistent/TailsDeadManSwitch/payloads
```

- This generates a GPG-encrypted JSON bundle for manual transfer.

---

##  Configuration

Configuration is stored in `~/.config/tails-dms/config.json` (or as prompted during `--init`).

Key fields:

- `heartbeat_interval` (seconds)
- `mode` (`tor` or `airgap`)
- `action` (array of action objects)
- `log_path` (audit chain)

Example action object:

```json
{
  "type": "shred",
  "target": "/home/user/sensitive.txt",
  "retries": 3
}
```

---

##  Security Notes

- Always run from Persistent Storage. Unsaved changes are discarded after reboot in Tails.
- Keep similar logic for external scripts; avoid storing secrets in plaintext.
- Validate the hash chain after each session before trusting action outcomes.

---

##  Troubleshooting

- If the UI fails to load, check `GTK_PATH` and confirm `python3-gi` is installed.
- If GPG errors occur in air-gap mode, verify the keypair with `gpg --list-secret-keys`.
- For permission errors, ensure your Tails persistence folder is unlocked and writable.

---

##  Testing

- Manual validation is core to this project:
  - Arm in a controlled environment.
  - Disable check-ins and ensure action triggers as expected.
  - Inspect `audit.log` chain and run `--verify`.

---

##  Contributing

- Fork, branch, and open a pull request.
- Maintain minimal dependency posture and readability.
- Add tests for edge cases (invalid config, stale log chain, missing persistence).

---

##  License

MIT License — see `LICENSE`.
