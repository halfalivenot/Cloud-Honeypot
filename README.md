# Cloud-Honeypot
Designed and deploy a honeypot in Google Cloud Platform.

Create a VM, configure it access it to the public Internet, and allow it to run for an extended period of time. Log forwaring and failed login attacks to forward the logs into a repository, which is then connected to a SIEM. (Then be able to query from that SIEM and create an attack map that shows where all the attackers are from)

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
Looker Studio Attack Map (Data Studio)


## Part 1: Create Honeypot VM
Manage resources -> Create project -> "honeypot-lab"
![screenshots](screenshots/scrn1.png)

Enable Compute Engine and Cloud Logging APIs
Create VM instance
![screenshots](screenshots/scrn2.png)
Don't forget to enable "Install Ops Agent"
![screenshots](screenshots/scrn3.png)
I sucessfully logged into my VM remotely.
![screenshots](screenshots/scrn4.png)

### Disble firewall
Go to VPC -> Firewall -> Add firewall rule
"Allow-all-ingress"
![screenshots](screenshots/scrn5.png)

Back in the Windows VM, I went to Windows Defender Firewall, click on Properties, and turned off the firewall for Domain Profile, Private Profile, and Public Profile. 
![screenshots](screenshots/scrn6.png)

## Part 2: Testing and verifying logs
I logged out of my Windows VM. I then failed three times as "employee" to login and then three more times as "admin." Afterwards, I logged in properly and checked what logs I've generated in Event Manager. 
![screenshots](screenshots/scrn7.png)

## Part 3: Logging Pipeline and Configuration
In the Windows VM, I went to the following path to configure the config.yaml file for Ops Agent. 
```
C:\Program Files\Google\Cloud Operations\Ops Agent\config
```
In the config.yaml file, I added the following:
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
![screenshots](screenshots/scrn8.png)
After saving my changes, I went to PowerShell as Administrator. I stop and start the service to ensure my changes occured.
```
Stop-Service -Name "google-cloud-ops-agent" -Force
Start-Service -Name "google-cloud-ops-agent"
Get-Service -Name "google-cloud-ops-agent"
```
![screenshots](screenshots/scrn8.png)

Going to Monitoring -> Logs Explorer
```
resource.type="gce_instance"
"4625"
```
I verified that my logs were being properly pipelined. 
![screenshots](screenshots/scrn9.png)
![screenshots](screenshots/scrn10.png)

## Part 4: BigQuery Dataset, Configure Logs to go to this Dataset
In BigQuery Studio, I create a dataset called "honeypot_logs"
![screenshots](screenshots/scrn11.png)

Back in Monitoring, I went to Log Router and Create Sink to send my Logs to my dataset.
![screenshots](screenshots/scrn12.png)

In BigQuery Studio, I verifiy if my logs went through.
![screenshots](screenshots/scrn13.png)

## Part 5: GeoIP Database
I downloaded GeoIP and uploaded to BigQuery Studio as a dataset "reference_data"
```
BigQuery Studio
Create dataset: reference_data
Upload: geoip_summarized.csv
Create table: geoip
Auto-Detect fields
```
![screenshots](screenshots/scrn14.png)

## Part 6: Create queries and views
failed logins query
![screenshots](screenshots/scrn15.png)

creating failed_logins
![screenshots](screenshots/scrn16.png)

enriched query
![screenshots](screenshots/scrn17.png)

creating enriched failed logins
![screenshots](screenshots/scrn18.png)


## Part 7: Attack Map creation
![screenshots](screenshots/scrn19.png)


At this point, I decided to leave the VM on for a day to left it to attacked. 



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


Part 12 + 13
failed logins query
```
SELECT
  timestamp,
  jsonPayload.computername AS host,
  jsonPayload.eventid AS event_id,
  jsonPayload.stringinserts[SAFE_OFFSET(19)] AS attacker_ip,
  jsonPayload.message
FROM `honeypot-lab-498217.honeypot_logs.windows_event_log_20260602`
WHERE jsonPayload.eventid = 4625
ORDER BY timestamp DESC;
```
creating failed_logins view
```
CREATE OR REPLACE VIEW `honeypot-lab-498217.honeypot_logs.failed_logins` AS
SELECT
  timestamp,
  jsonPayload.computername AS hostname,
  jsonPayload.eventid AS event_id,
  jsonPayload.stringinserts[SAFE_OFFSET(19)] AS attacker_ip,
  jsonPayload.message
FROM `honeypot-lab-498217.honeypot_logs.windows_event_log_20260602`
WHERE jsonPayload.eventid = 4625;
```
enriched query
```
WITH failed_logins AS (
  SELECT
    timestamp,
    jsonPayload.computername AS host,
    jsonPayload.stringinserts[SAFE_OFFSET(19)] AS attacker_ip
  FROM `honeypot-lab-498217.honeypot_logs.windows_event_log_20260602`
  WHERE CAST(jsonPayload.eventid AS INT64) = 4625
),

geoip AS (
  SELECT
    network,
    countryname,
    cityname,
    latitude,
    longitude,
    NET.SAFE_IP_FROM_STRING(SPLIT(network, '/')[OFFSET(0)]) AS net_ip,
    CAST(SPLIT(network, '/')[OFFSET(1)] AS INT64) AS prefix
  FROM `honeypot-lab-498217.reference_data.geoip`
)

SELECT
  f.timestamp,
  f.host,
  f.attacker_ip,
  g.countryname,
  g.cityname,
  g.latitude,
  g.longitude
FROM failed_logins f
JOIN geoip g
ON NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(f.attacker_ip), 16) = g.net_ip
ORDER BY f.timestamp DESC;
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

