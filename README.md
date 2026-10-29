# Microsoft-Sentinel-Workbook-Threat-Intelligence-Correlated-Inbound-Brute-Force-Geo-Mapping
Threat Hunting project utilizing Threat Intelligence.

### Microsoft Sentinel Workbook: Threat Intelligence-Correlated Inbound Brute-Force & Geo-Mapping
🎯 ###Project Overview & Objective
In modern Security Operations Centers (SOCs), analysts are constantly flooded with high volumes of authentication telemetry and brute-force alerts. The core challenge is signal-to-noise ratio: separating ordinary high-volume automated scanners from targeted, high-risk attacks originating from known malicious infrastructure.

The objective of this project was to build a custom Microsoft Sentinel workbook that moves beyond basic log monitoring. By cross-referencing live endpoint logon telemetry (DeviceLogonEvents) against active, non-expired threat intelligence feeds (ThreatIntelIndicators), this dashboard instantly surfaces inbound authentication attempts originating from known malicious public IP addresses.

Crucially, the workbook highlights successful vs. failed logons alongside targeted device counts and hostnames—allowing analysts to immediately prioritize investigations where a known hostile IP successfully breached an environment.

---

## 🏗️ Architecture & Data Flow
Threat Intelligence Watchlist (ThreatIntelIndicators): Ingests and filters active IP indicators (using STIX/TAXII indicator types), filtering out expired records and deduplicating indicators using arg_max().

Endpoint Inbound Telemetry (DeviceLogonEvents): Captures incoming public network and RDP logons (RemoteIPType == "Public", LogonType in ("Network", "RemoteInteractive")).

Correlation: Performs an inner join between live logons and active threat intelligence indicators based on matching source IP addresses.

Geo-Enrichment: Enriches the hostile IP using Sentinel’s native geo_info_from_ip_address() function to extract precise latitude, longitude, country, state, and city data.

Aggregation & Visualization: Summarizes total attack volume, success/failure ratios, distinct targeted devices, device names, and targeted user accounts to drive both a global map view and a structured triage grid.

---
## KQL Query Implementation
The underlying logic powering the workbook is structured into the following Kusto Query Language (KQL) query:
```kusto
// === Threat Intelligence Brute-Force & Geo-Mapping Query ===
// Step 1: Pull active IP indicators using valid ThreatIntelIndicators schema
let TI_IPs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsActive == true
    | where isempty(ValidUntil) or ValidUntil > now()
    | where ObservableKey in ("ipv4-addr:value", "network-traffic:src_ref.value", "network-traffic:dst_ref.value")
    | extend ThreatType = tostring(Data.indicator_types[0])
    | project TI_IP = ObservableValue, Confidence, ThreatType, Tags
    | where isnotempty(TI_IP);

// Step 2: Ingest inbound public logon events and join against known malicious TI IPs
DeviceLogonEvents
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| join kind=inner (TI_IPs) on $left.RemoteIP == $right.TI_IP

// Step 3: Enrich with geolocation data (Country, State, City, Lat/Long)
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Country = tostring(geo.country),
         State   = tostring(geo.state),
         City    = tostring(geo.city),
         Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude)
| where isnotempty(Latitude) and isnotempty(Longitude)

// Step 4: Summarize metrics (Attempts, Failures, Successes, Device Count, Device Names, & Users)
| summarize TotalAttempts   = count(),
            Failures        = countif(ActionType == "LogonFailed"),
            Successes       = countif(ActionType == "LogonSuccess"),
            TargetedDevices = dcount(DeviceName),
            DeviceNames     = make_set(DeviceName, 10),
            ThreatTypes     = make_set(ThreatType, 10),
            TargetedUsers   = make_set(AccountName, 10)
         by RemoteIP, Country, State, City, Latitude, Longitude

// Step 5: Format map labels and structure final grid/map output
| extend MapLabel = strcat(RemoteIP, " (", City, ", ", State, ", ", Country, ") — ", Failures, " fails / ", TotalAttempts, " total")
| project Latitude, Longitude, MapLabel, RemoteIP, Country, State, City, TotalAttempts, Failures, Successes, TargetedDevices, DeviceNames, TargetedUsers
| order by TotalAttempts desc
```
---

## 📊 Workbook Visualization & Triage Interface
The dashboard combines an interactive global map (where bubble size represents total attack volume and color coding highlights the failure-to-success ratio) with a granular triage table underneath.

<img width="1024" height="523" alt="image" src="https://github.com/user-attachments/assets/dc08b6e4-c639-451b-b7cd-9b34f51734f8" />

---
### Key Analyst Takeaways from the View:
Global Threat Mapping: Instantly pinpoints geographic hotspots conducting high-volume brute-force attempts against tenant endpoints.

Granular Asset Visibility: Tracks exact target counts alongside explicit hostnames (DeviceNames) and targeted accounts (TargetedUsers) to determine blast radius.

Risk Prioritization: Separates routine scanning activity from high-priority compromises where known malicious infrastructure achieved successful authentication.

---

## 🔍 Case Study: Investigating High-Risk Suspicious Infrastructure

A key strength of this dashboard is its ability to move beyond high-volume noise to uncover specific bad actors that warrant immediate escalation. 

For example, when isolating high-attempt external entities in the workbook grid, the dashboard flagged `80.94.95.83` (originating from Romania)[cite: 9] executing over **13,000 total attempts**[cite: 9] against **48 distinct target devices**[cite: 9]. 


<img width="1555" height="473" alt="image" src="https://github.com/user-attachments/assets/a2a481bb-e712-4f9a-89a3-94f2205a0167" />
<img width="635" height="896" alt="image" src="https://github.com/user-attachments/assets/e36a7494-3e0b-40b1-9dcd-f25118aaf495" />


### Analyst Triage Steps:
1. **Volume Analysis:** Noticed heavily skewed failure counts (`12,976` failures)[cite: 9] indicating automated brute-force tool usage.
2. **Compromise Verification:** Crucially checked the `Successes` column, identifying that this specific hostile IP managed to achieve **48 successful authentications**.
3. **Blast Radius Assessment:** Examined the `DeviceNames` and `TargetedUsers` arrays[cite: 9] to immediately scope which corporate endpoints and user accounts were compromised, triggering downstream incident response.
