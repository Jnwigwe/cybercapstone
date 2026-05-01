# Rootkit Detection Test – User-Space Demo

## Environment
All testing was performed on Kali Linux as a user-space proof-of-concept.  
The goal of this test was to verify whether my PID screamer and heuristic scanner could detect:
- a compiled hidden backdoor binary running from `~/Downloads`
- a fake rootkit-style binary
- active suspicious processes
- suspicious file paths during directory scans

This is **not kernel-level detection**. Everything here is intentionally user-space focused.

---

## Initial Setup

I started by confirming the tools were present and executable.

- `pid_screamer` located in `~/rootkit-tools`
- test binaries located in `~/Downloads`
  - `rk_hidden_backdoor`
  - `rk_fake_rootkit`

The `.c` source files themselves were **not expected to be detected**, since the scanner is process-based and binary-focused. Only compiled and running executables should show up.

---

## First Scan – Hidden Backdoor Detection

After compiling and running the hidden backdoor binary from `~/Downloads`, I ran the PID screamer scan.

The scan walked over the filesystem and finished with this summary:

- Directories walked: **1167**
- Files scanned: **14886**

The suspicious process report showed the following active processes:

- PID **29959** → `/home/tr33/rootkit-tools/pid_screamer`
- PID **28977** → `/home/tr33/Downloads/rk_hidden_backdoor`
- PID **27778** → `/home/tr33/Downloads/rk_hidden_backdoor`

This confirmed that:
- the backdoor binary was running
- the process name and path were successfully picked up
- multiple instances of the same suspicious binary were detected correctly

The scan completed successfully and saved the results to `suspicious_report.txt`.

---

## Fake Rootkit Execution Test

Next, I executed the fake rootkit-style program from `~/Downloads`.

While running, it continuously printed status output similar to:

