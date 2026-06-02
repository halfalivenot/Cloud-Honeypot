# Cloud-Honeypot
Designed and deploy a honeypot in Google Cloud Platform.

Create a VM, configure it access it to the public Internet, and allow it to run for an extended period of time. Log forwaring and failed login attacks to forward the logs into a repository, which is then connected to a SIEM. (Then be able to query from that SIEM and create an attack map that shows where all the attackers are from)

|Azure Lab | GCP Equivalent |
|---|----|
|Azure VM | Compute Engine VM |
|Network Security Group (NSG) | VPC Firewall Rules |
|Windows Event Logs |Windows Event Logs |
|Log Analytics Workspace (LAW) |Cloud Logging (Operations Suite) |
|Microsoft Sentinel | Google Security Operations (Chronicle) or Cloud Logging + BigQuery|
|KQL | Logging Query Language / BigQuery SQL |
|Sentinel Watchlist | BigQuery reference table / Chroncicle reference list |
| Sentinel Workbook | Looker Studio Dashboard / Chroncicle Dashboard |

To do list:
- Create a project
- Create a VPC network
- Configure VPC firewall rules (turn it off)
- Create a VM (Windows 10)
- Turn off firewall rules within Windows (Access it through RDP)
- Ping from my computer to test
- Attempt to fail to login into VM 
- Go to VM Windows EventManager and see failed logins (Event ID: 4626)
- Go to Cloud Logging
- Connect Google Security Operations (Cloud-native SIEM)

Skills Learned
- Centralized logging
- Security Event Analysis
- Querying
- Enrichment
- Threat Hunting
- Attack Visualization

Architecture
Internet Attackers
        │
        ▼
Windows Honeypot VM
        │
        ▼
Cloud Logging
        │
        ▼
Log Router Sink
        │
        ▼
BigQuery
        │
        ▼
GeoIP Enrichment
        │
        ▼
Looker Studio Attack Map

## Part 1: Create the project & Honeypot VM
In GCP, enable Compute Engine, Cloud Logging API, etc.
Name: WD-CORP-SOUTH-01 (to hide that its a honeypot)
Type: e2-medium
OS: Windows Server 2022
Region: us-south

### Open it to the Internet
VPC Network -> Firewall -> Create Firewall Rule
Name: allow-all-ingress
Direction: Ingress
Source: 0.0.0.0/0
Protocols: All
Action: Allow

### Disable Windows Firewall
Connect using RDP
Open Windows Firewall and click on Properties
Disble and turn off Domain Profile, Private Profile, Public Profile

## Part 2: Generate Security Events
from the windows login screen, attempt login with wrong password three times

## Part 3: Verify Event Logs
Event Viewer
Windows Logs -> Security
Event ID 4625

## Part 4: Install the Google Ops Agent
On the VM, open PowerShell as Admin. 
```
Invoke-WebRequest `
https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.ps1 `
-OutFile add-google-cloud-ops-agent-repo.ps1

.\add-google-cloud-ops-agent-repo.ps1
```
Verify
```
Get-Service google-cloud-ops-agent
```

## Part 5: Collect Windows Security Logs
Edit Ops Agent configuration
File: 
```
C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.yaml
```
example:
```
logging:
  receivers:
    windows_security:
      type: windows_event_log
      channels:
        - Security

  service:
    pipelines:
      security_pipeline:
        receivers:
          - windows_security
```
Restart:
```
Restart-Service google-cloud-ops-agent
```

## Part 6: Verify Logs in Cloud Logging
Open Logs Explorer
Query:
```
resource.type="gce_instance"
```
check if vm logs are appearing
Search for 4625:
```
resource.type="gce_instance"
"4625"
```
I should see my failed logins


## Part 7: Create BigQuery Dataset
Open: BigQuery Studio
Create Dataset: honeypot_logs
Region: us-south

## Part 8: Export Logs to BigQuery
Go to Cloud Logging -> Log Router
Create sink: 
Name: honeypot-security-events 
Destination: BigQuery Dataset
Choose: honeypot_logs
Filter: resource.type="gce_instance"

## Part 9: Verify Data in BigQuery
Run:
```
SELECT *
FROM `PROJECT_ID.honeypot_logs._AllLogs`
LIMIT 10;
```

## Part 10: Download GeoIP Database
https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/misc/geoip-summarized.csv?utm_source=chatgpt.com 

## Part 11: Import GeoIP into BigQuery
Create dataset: reference_data
Upload: geoip-summarized.csv
Create table: geoip
Columns include:
```
network
city
country
latitude
longitude
```

## Part 12: Query Failed Logins
Create a query for Event ID 4625.

The exact field names vary depending on how the Windows logs arrive, but conceptually:
```
SELECT
  timestamp,
  jsonPayload.EventID,
  jsonPayload.TargetUserName,
  jsonPayload.IpAddress
FROM
  `PROJECT_ID.honeypot_logs.logs`
WHERE
  jsonPayload.EventID = 4625
ORDER BY timestamp DESC
```
Goal:

Identify:

Attacker IP
Username targeted
Time of attack

## Part 13: Creat Enriched Attack Data
Create a view.

Example:
```
SELECT
  l.timestamp,
  l.ip_address,
  g.country,
  g.city,
  g.latitude,
  g.longitude
FROM
  failed_logins l
JOIN
  geoip g
ON
  l.network = g.network
```
The exact join logic depends on your IP format.

Result:
```
IP
Country
City
Latitude
Longitude
Timestamp
```
This reproduces the Sentinel watchlist enrichment step.

## Part 14: Build the Attack Map
Open Looker Studio (Data Studio, buy a trial for one month)
Create: Report
Add Data Source: BigQuery
Choose: enriched_failed_logins

### Create Geo Map
Insert: Geo Chart
Map:
| Field     | Value     |
| --------- | --------- |
| Latitude  | latitude  |
| Longitude | longitude |
| Metric    | COUNT(*)  |
You now have a live attack map

## Part 15: Additional Dashboard Widgets
### Failed Logins by Country
Dimension: country
Metric: count

### Top Attacker IPs
Dimension: ip_address
Metric: count

### Attacks Over Time
Dimension: timestamp
Metric: count

## Part 16: Threat Hunting Exercises
Open the VM is exposed for a day or two, investigate: 
### Most Targeted Usernames
```
SELECT
  username,
  COUNT(*) attacks
FROM failed_logins
GROUP BY username
ORDER BY attacks DESC
```
### Top Countries
```
SELECT
  country,
  COUNT(*) attacks
FROM enriched_failed_logins
GROUP BY country
ORDER BY attacks DESC
```
### Top Source IPs
```
SELECT
  ip_address,
  COUNT(*) attacks
FROM failed_logins
GROUP BY ip_address
ORDER BY attacks DESC
```

