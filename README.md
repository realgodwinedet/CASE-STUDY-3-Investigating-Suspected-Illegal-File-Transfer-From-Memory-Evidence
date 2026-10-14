# FORENSIC INVESTIGATION REPORT: CASE STUDY 3
## Investigating Suspected Illegal File Transfer From Memory Evidence

---

### Report Metadata
| Field | Details |
| :--- | :--- |
| **Course** | SBT-DF204 — Computer Forensics Case Studies |
| **Assessment** | Individual memory forensics investigation |
| **Student Name** | Godwin Edet Ikpi |
| **Registration Number** | 2025/FWSD/11267 |
| **Evidence Image** | `memdumpWin7.mem` |
| **Primary Tool** | Volatility 2 (Python 2 environment) |
| **Report Status** | Final Submission |

---

## 1. Case Reference and Student Identification
* **Case Title:** Investigating Suspected Illegal File Transfer From Memory Evidence
* **Case Reference:** SBT-DF204 Case Study 3
* **Student Name:** Godwin Ikpi
* **Registration Number:** 2025/FWSD/11267

This is an individual offline examination of the supplied Windows memory image named `memdumpWin7.mem`. The purpose was to assess whether the available memory and associated artefacts support a defensible sequence involving browser or process activity, command-line activity, removable media, a user profile, and File Explorer traces.

---

## 2. Executive Conclusion
The examination of `memdumpWin7.mem` identified a coherent set of artefacts consistent with a possible file-transfer attempt. The strongest supporting observations were an active SSH service (`sshd.exe` PID 2016) bound to listening network sockets, command-history records executing `ipconfig`, `cd Downloads`, and `copy secret_file.docx F:`, and an absence of active USB storage or mapped drive records in the volatile snapshot, recorded as evidence IDs **[E03, E04, E05]**.

These artefacts **DO NOT** establish that the transfer completed. On the current evidence, confidence in the conclusion that a transfer may have been attempted is **MODERATE**, while confidence that a named individual performed a completed unauthorized transfer is **NOT ESTABLISHED**.

---

## 3. Scope, Authority, and Questions
**Scope:** Offline analysis of the authorised teaching image only. No recovered endpoint, host, account, file-sharing service, or person is to be contacted. Recovered files must not be executed, and password or hash-cracking steps are outside this case study. 

The investigation addresses:
1. Acquisition and integrity
2. Operating-system profile and image time
3. User/account artefacts
4. Process and network artefacts
5. Command history
6. Removable-media and drive-mapping evidence
7. File Explorer/ShellBag evidence
8. A UTC timeline and cautious conclusion

---

## 4. Evidence Acquisition and Integrity
The assessment brief identifies the supplied image as `memdumpWin7.mem`. Analysis was performed strictly on an isolated working copy while maintaining read-only permissions on the source image.

| Field | Recorded Value |
| :--- | :--- |
| **Evidence ID** | E01 |
| **Original Filename** | `memdumpWin7.mem` |
| **Source / Supplied Location** | `/home/kali/Downloads/memdumpWin7(1).mem` |
| **Original File Size** | 1,073,676,288 bytes (1.0 GB) |
| **Original SHA-256** | `500bc1ba8b55fa8053b6213d7e7aae0c84c18cce541dc53a5587e6e5099495e` |
| **Working-Copy Path** | `/home/kali/memdumpWin7.mem` |
| **Working-Copy SHA-256** | Matches the original SHA-256 hash |
| **Acquisition Date/Time** | 2026-10-12 13:13 WAT |
| **Tools & Versions** | `sha256sum` (GNU coreutils 9.5), Volatility Framework 2.6, Kali Linux Rolling |

### 4.1 Acquisition Commands Used
```bash
ls -l --full-time /path/to/memdumpWin7.mem
stat /path/to/memdumpWin7.mem
sha256sum /path/to/memdumpWin7.mem
cp --preserve=all /path/to/memdumpWin7.mem /path/to/working/memdumpWin7_working.mem
sha256sum /path/to/working/memdumpWin7_working.mem

```

---

## 5. Method and Profile Selection

### 5.1 Image Identification

* **Command:** `python2 vol.py -f memdumpWin7.mem imageinfo`
* **Suggested Profiles:** `Win7SP1x86_23418`, `Win7SP0x86`, `Win7SP1x86` (Evidence ID: E02)
* **Selected Profile:** `Win7SP1x86` (Evidence ID: E02)
* **Image Capture Time:** 2019-01-06 15:09:06 UTC (Local: 07:09:06 -0800)
* **Time Zone Basis:** UTC / System Local Basis (-08:00)

**Profile Validation:** The selected profile `Win7SP1x86` successfully parsed the kernel structure by locating a valid KDBG header (`0x82972c68L`) and correctly handling the 32-bit PAE memory layer (`IA32PagedMemoryPae`). It enabled clean, error-free artifact extraction across process lists (`pslist`), network connections (`netscan`), and command histories (`cmdscan`).

### 5.2 Examination Commands

```bash
# Process List
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 pslist

# Process Scan
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 psscan

# Network Scan
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 netscan

# Command History
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 cmdscan

# Console History
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 consoles

# Registry Hives
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 hivelist

# USB Storage Artifacts
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 printkey -K "ControlSet001\Enum\USBSTOR"

# Mount Points / Explorer History
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

# Shellbags Analysis
./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 shellbags

```

---

## 6. Findings

### 6.1 User and Account Artefacts

* **Command Used:** `hivelist` followed by registry hive inspection.
* **Observed Artefacts:** User profile activity is associated with standard local user accounts residing under `C:\Users\`, with registry paths mapped through the SAM and DEFAULT hives.
* **Interpretation:** Maps interactive logon sessions and profile directory structures to a specific Windows account context rather than proving physical workstation presence at the exact time of execution.
* **Evidence ID:** E02; Appendix A-3

### 6.2 Process and Network Evidence

| Artefact | Verified Observation | Interpretation and Limitation | Evidence ID |
| --- | --- | --- | --- |
| **Process Record** | `sshd.exe` (PID: 2016, Start Time: 2019-01-06 18:02:44 UTC) alongside `cmd.exe` (PID: 3988, associated with `conhost.exe`). | Indicates active remote administration via SSH and command shell execution. Process names alone do not confirm malicious intent without verification. | E03 |
| **Network Record** | TCPv4 listening endpoints on port 22 (`sshd.exe`, PID 2016) and CLOSED TCP connections on port 80. | Reflects active SSH service binding and historical web socket activity. Connection existence does not prove files were successfully transmitted. | E04 |
| **Memory String / Record** | Direct command-line artifacts captured via `cmdscan`: `ipconfig`, `cd Downloads`, and `copy secret_file.docx F:` (PID: 3988). | Provides corroborating evidence of user interaction, folder navigation, and file staging/copying activity to a secondary drive (`F:`). | E04 |

### 6.3 Command History

* **Plugin & Command:** `./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 cmdscan`
* **Process / PID:** `cmd.exe` (Associated with `conhost.exe`, PID: 3988)
* **Recovered Command Text:** `ipconfig`, `cd Downloads`, `copy secret_file.docx F:`
* **Evidence ID:** E04 / Appendix A-4

**Interpretation:** The sequence reveals network reconnaissance (`ipconfig`), directory traversal into the user's download directory (`cd Downloads`), and an explicit file staging attempt copying a sensitive document (`secret_file.docx`) to a secondary drive volume (`F:`). Unless corroborated by physical drive artifacts, the presence of a copy command does not definitively establish that the destination volume was writable or that the transfer completed.

### 6.4 Removable-Media and Drive-Mapping Evidence

| Source Artefact | Path / Record | Verified Value | What it may support | What it does not prove | Evidence ID |
| --- | --- | --- | --- | --- | --- |
| **USBSTOR** | `ControlSet001\Enum\USBSTOR` | Not observed / No active USB storage device identifiers resident. | A device-identification artefact in the registry. | Physical possession by a named person or use at exact transfer time. | E05 |
| **DeviceClasses** | `ControlSet001\Control\DeviceClasses` | Not observed / No corresponding device interface GUIDs resident. | Device/interface association. | That files were copied to the device. | E05 |
| **MountedDevices** | `ControlSet001\Control\MountedDevices` | Not observed / No persistent volume letter or GUID signatures mapped. | Volume or drive-letter mapping evidence. | That a specific copy operation succeeded. | E05 |
| **MountPoints2** | `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Not observed / No user-profile hive shell references mapped for drive `F:`. | A profile-associated volume/shell reference. | Identity of the person at the keyboard. | E05 |

### 6.5 File Explorer and ShellBag Evidence

An inspection of the memory image for File Explorer and ShellBag artifacts did not recover persistent bag structures or user-profile folder-view registry keys in volatile memory. While ShellBag entries reside primarily within non-volatile user registry hives (`NTUSER.DAT`), directory access to `Downloads` is strongly corroborated by the interactive `cmdscan` history.

* **Evidence ID:** E06 / Appendix A-6

---

## 7. UTC Timeline and Reconstruction

| Stage | UTC Timestamp | Evidence ID | Source Artefact | Observed Fact | Interpretation and Limit |
| --- | --- | --- | --- | --- | --- |
| **Image Capture** | 2019-01-06 15:09:06 UTC | E02 | `imageinfo` | Kernel initialization and memory dump timestamp recorded. | High reliability; represents acquisition time, not incident time. |
| **Process Evidence** | 2019-01-06 18:02:44 UTC | E03/E04 | Process/Network records | Core system and service processes (such as `sshd.exe`, PID 2016) initialized. | Indicates when binaries spawned; does not prove ongoing user intent. |
| **Download Folder** | UNKNOWN | E06 | ShellBag structures | No persistent folder-view records actively resident in volatile memory. | Absence in volatile memory does not mean interaction never occurred. |
| **Removable Device** | UNKNOWN | E05 | `USBSTOR` / `DeviceClasses` | No active USB storage identifiers or persistent volume keys observed. | Volatile registry state may lack unmounted hardware signatures. |
| **Drive Mapping** | UNKNOWN | E05 | `MountedDevices` | Drive letter `F:` referenced in command buffer, but mapping keys unobserved. | Volatile memory captures live states and may omit unmounted volume keys. |
| **Command History** | UNKNOWN | E04 | `cmdscan` / `consoles` | Recovered sequence: `ipconfig`, `cd Downloads`, `copy secret_file.docx F:`. | Confirms operator typing/intent within console buffer; requires file system corroboration. |

---

## 8. Attribution Assessment

1. **Memory-Capture Timing & Volatility:** Artifacts recovered from active buffers represent a static point-in-time snapshot (2019-01-06 15:09:06 UTC) and may be transient or incomplete.
2. **Profile Versus Person Context:** Process ownership and session IDs indicate workstation configuration and process ownership rather than proving the physical presence or identity of the individual operating the keyboard.
3. **Command Success & Exfiltration Limits:** The recovered command sequence (`copy secret_file.docx F:`) demonstrates explicit operator input and file staging intent, but does not prove the command executed successfully or that exfiltration completed.
4. **Absence of Corroborating Storage:** Examination of low-level structures (`USBSTOR`, `MountedDevices`, `ShellBags`) yielded no active evidence of drive `F:` within the volatile memory snapshot.

---

## 9. Conclusion and Confidence

* **Completed transfer established?** **NOT ESTABLISHED**, because while command-line history (`E04`) indicates an explicit attempt to copy `secret_file.docx` to drive `F:`, volatile registry and drive-mapping artifacts (`E05`) contain no active persistence or volume mapping for drive `F:`.
* **Attribution to a named individual established?** **NOT ESTABLISHED**, because technical artifacts reflect workstation and session state rather than proving the physical presence or identity of the individual operating the keyboard.
* **Confidence Level:** **MODERATE** for the proposition that an operator initiated a file-copy command within an interactive shell session, based on corroborating volatile console and process memory sources (`E03`, `E04`).

---

## 10. Evidence Log

| Evidence ID | Tool / Plugin & Version | Exact Command / Source Path | Observed Fact (Not Inference) | Screenshot / Appendix |
| --- | --- | --- | --- | --- |
| **E01** | `sha256sum` (Coreutils 9.5) | `sha256sum ~/Downloads/memdumpWin7.mem` | SHA-256 hash value `500bc1ba8b55fa8053b6213d7e7aae0c84c18cce541dc53a5587e6e5099495e` (Size: 1.0 GB) verified. | Appendix A-1 |
| **E02** | Volatility 2 `imageinfo` | `./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem imageinfo` | Identified KDBG header at `0x82972c68L`, profile `Win7SP1x86`, and capture time 2019-01-06 15:09:06 UTC. | Appendix A-2 |
| **E03** | Volatility 2 `pslist` / `psscan` | `./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 pslist` | Extracted process structures including System, smss.exe, csrss.exe, and sshd.exe (PID 2016). | Appendix A-3 |
| **E04** | Volatility 2 `netscan` / `cmdscan` | `./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 cmdscan` | Extracted network connections (listening port 22) and command history buffer (`ipconfig`, `cd Downloads`, `copy secret_file.docx F:`). | Appendix A-4 |
| **E05** | Volatility 2 `hivelist` / `printkey` | `./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 hivelist` | Parsed volatile registry hives; no active USB storage or persistent volume mappings for drive `F:` observed. | Appendix A-5 |
| **E06** | Volatility 2 `shellbags` | `./volatility_2.6_lin64_standalone -f ~/memdumpWin7.mem --profile=Win7SP1x86 shellbags` | Scanned for File Explorer structures; no persistent folder-view registry bags actively resident in volatile memory. | Appendix A-6 |

---

## 11. Appendices and Screenshot Register

| Appendix | Required Content | Status / Filename |
| --- | --- | --- |
| **A-1** | Acquisition details, file size, original and working-copy SHA-256 | `evidence/A1_acquisition.txt` |
| **A-2** | `imageinfo` output and profile-validation notes | `evidence/A2_imageinfo.txt` |
| **A-3** | `pslist` and `psscan` outputs showing relevant process records | `evidence/A3_pslist.txt` |
| **A-4** | `netscan`, `cmdscan`, and `consoles` outputs | `evidence/A4_cmdscan_netscan.txt` |
| **A-5** | `hivelist` and relevant USBSTOR, DeviceClasses, MountedDevices records | `evidence/A5_registry.txt` |
| **A-6** | ShellBag HTML output and relevant folder records | `evidence/A6_shellbags.txt` |
| **A-7** | Completed UTC timeline and expanded evidence log | Integrated in Report
