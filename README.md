<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user”employee” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop. These events began at: 2025-09-17T19:43:23.3869547Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-tom"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-17T19:43:23.3869547Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1161" height="418" alt="image" src="https://github.com/user-attachments/assets/509f1bfd-9cfb-4b0c-a2bc-6eed9ca19594" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-14.5.7.exe”. Based on logs returned, At 2025-09-17T19:45:27.9258192Z, someone using the account employee on the device named threat-hunt-tom launched the program tor-browser-windows-x86_64-portable-14.5.7.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-tom"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1171" height="225" alt="image" src="https://github.com/user-attachments/assets/22775dfe-97ef-415b-9159-d3a05e0725eb" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “employee” actually opened the tor browser. There was evidence that they did open it at 2025-09-17T19:45:55.9958199Z.
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-tom"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser-windows-x86_64-portable-14.5.7.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1156" height="406" alt="image" src="https://github.com/user-attachments/assets/154234d0-396f-4e77-8fc0-f929347cca8c" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-09-17T19:46:51.0624867Z on the computer threat-hunt-tom, the user employee successfully connected out (over port 9001) to the remote IP address 94.16.113.135 using the program tor.exe, which was launched from C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-tom"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", " 9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1160" height="409" alt="image" src="https://github.com/user-attachments/assets/4c5ba71b-7e6e-4a78-86fb-6551e244a0a0" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-17T19:43:23.3869547Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-17T19:45:27.9258192Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-17T19:45:55.9958199Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-17T19:46:51.0624867Z`
- **Event:** A network connection to IP `94.16.113.135` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamp:**
  - `2025-09-17T19:46:54.7678524Z` - Local connection to `64.65.0.67` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Successful connections detected.


---

## Summary

The user "employee" on the "threat-hunt-tom" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-tom` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
