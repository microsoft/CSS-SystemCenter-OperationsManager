![Data Collector](/media/git-guidance/projects/scom-data-collector.png)

## Download Link
[https://aka.ms/SCOM-DataCollector](https://aka.ms/SCOM-DataCollector)

[![Download Count Latest](https://img.shields.io/github/downloads/blakedrumm/SCOM-Scripts-and-SQL/latest/SCOM-DataCollector.zip?style=for-the-badge&color=brightgreen)](https://aka.ms/SCOM-DataCollector) \
[![Download Count Releases](https://img.shields.io/github/downloads/blakedrumm/SCOM-Scripts-and-SQL/total.svg?style=for-the-badge&color=brightgreen)](https://github.com/blakedrumm/SCOM-Scripts-and-SQL/releases)

## Personal Webpage
[https://files.blakedrumm.com/SCOM-DataCollector.zip](https://files.blakedrumm.com/SCOM-DataCollector.zip)

## Blog Post
[https://blakedrumm.com/blog/scom-data-collector/](https://blakedrumm.com/blog/scom-data-collector/)

## Github Link
[https://github.com/blakedrumm/SCOM-Scripts-and-SQL/releases/latest](https://github.com/blakedrumm/SCOM-Scripts-and-SQL/releases/latest)

## Requirements
- System Center Operations Manager - Management Server
- Administrator Privileges
- Powershell 4

## Instructions
[Download the zip file](https://aka.ms/SCOM-DataCollector) and extract zip file to a directory (ex. C:\Data Collector). You have 2 options for running this script.
1. Right Click the SCOM Data Collector script and select Run with Powershell.
2. Open an Powershell shell __as Adminstrator__ and change to the directory the SCOM Data Collector Powershell Script is located, such as:
   ```powershell
   cd C:\Data Collector
   .\DataCollector-v4.0.0.ps1
   ```

 >### Optional
 >You have the ability to run this script as any user you would like when you start the script without any switches. The default is the System Center Data Access Service account.

Run this script on a Operations Manager Management Server to gather their SQL server names and DB names from the local registry. Otherwise user will need to manually input names. It will attempt to query the SQL Server Instance remotely, and will create CSV output files in the Output folder located in the SCOM Data Collector script directory.The SCOM Data Collector has the ability to query multiple databases in the SCOM SQL Instance (_master, OperationsManager, OperationsManagerDW_), having a high level of rights to SQL is preferred for a full gather.

After the script has completed you will see that the Output folder that is temporary created during script execution is removed. A zip file will be created in the same directory as the SCOM Data Collector Powershell Script named something similar to this: \
`SDC_Results_04_04_1975.zip`

This script has the ability to gather the following information:

 - Event Logs – Application, System, OperationsManager
 - SCOM Version Installed
 - Update Rollup Information for SCOM Upgrades
 - SQL Queries that collect information about many aspects of your environment (too many queries to go into detail here, here are some of the queries it uses: https://github.com/blakedrumm/SCOM-Scripts-and-SQL/tree/master/SQL%20Queries)
 - Windows Updates installed on Management Servers / SQL Server
 - Service Principal Name (SPN) Information for SCOM Management Servers
 - Local Administrators Group on each Management Server and any other servers you specify
 - Local User Account Rights on each Management Server and any other servers you specify
 - Database Information / DB Version
 - SCOM RunAs Account Information
 - Check TLS 1.2 Readiness
 - TLS Settings on each Management Server and SQL Server
 - MSInfo32
 - Sealed / Unsealed MPs
 - Clock Synchronization
 - Latency Check (Ping Test)
 - Rules / Monitors in your SCOM Environment
 - Get Run As Accounts from SCOM Management Group
 - Test SCOM Ports
 - Best Practice Analyzer to verify you are following SCOM Best Practices *(only a few items being checked currently)*
 - Gathers Group Policy settings on each Management Server and SQL Server
 - Gathers installed Software on each Management Server
 - Management Group Overall Health and verify Configuration matches across Management Servers in Management Group
 - Check SCOM Certificates for Validity / Usability
 - SCOM Install / Update Logs
 - IP Address of each Management Server
 - Gather SCOM Configuration from registry and configuration file
 - ***this list is not complete...***

----

## Examples

>### Optional
>If you know you have (read) Query rights against the DB(s) and Administrator permissions on the Management Servers, run any Switch (-Command) with -AssumeYes (-Yes). Otherwise you will need to provide an account that has permissions at runtime.


### Available Switches
Every Switch Available:

```powershell
.\DataCollector.ps1 -All -ManagementServers "<array>" -Servers "<array>" -AdditionalEventLogs "<array>" -GetRulesAndMonitors -GetRunAsAccounts -CheckTLS -CheckCertificates -GetEventLogs -ExportMPs -GPResult -SQLLogs -CheckPorts -GetLocalSecurity -GetInstalledSoftware -GetSPN -AssumeYes -GetConfiguration -CheckGroupPolicy -GetInstallLogs -SkipSQLQueries -SQLOnly -SQLOnlyOpsDB -SQLOnlyDW -BuildPipeline -CaseNumber "<string>" -ExportSCXCertificates -ExportMSCertificates -GenerateHTML -GetNotificationSubscriptions -GetUserRoles -LeastAmount -MSInfo32 -NoSQLPermission -PingAll -SCXAgents "<array>" -SCXUsername "<string>" -SCXMaintenanceUsername "<string>" -SCXMonitoringUsername "<string>" -SkipBestPracticeAnalyzer -SkipConnectivityTests -SkipGeneralInformation -SQLLogs
```


### All Switches
This will allow you to run every switch available currently:

```powershell
.\DataCollector.ps1 -All
.\DataCollector.ps1 -All -Servers Agent1
.\DataCollector.ps1 -All -Servers Agent1 -ManagementServer MS01-2019.contoso.com
.\DataCollector.ps1 -All -Yes
```


### Built in menu
To see the built in menu, run the script with no arguments or switches:

```powershell
.\DataCollector.ps1
```
You can also right click the `.ps1` file and Run with Powershell.


### Certificates
To Check the Certificate(s) Installed on the Management Server(s) in the Management Group, and an Server:

```powershell
.\DataCollector.ps1 -CheckCertificates -Servers AppServer1.contoso.com
```

To Check the Certificate(s) Installed on the Management Server(s) in the Management Group:

```powershell
.\DataCollector.ps1 -CheckCertificates
```

### Gather only SQL Queries
To gather only the SQL Queries run the following:

```powershell
.\DataCollector.ps1 -SQLOnly
```

If you know the account running the Data Collector has permissions against the SCOM Databases, run this:

```powershell
.\DataCollector.ps1 -SQLOnly -Yes
```



### Event Logs
To gather Event Logs from 3 Agents and the Management Server(s) in the Current Management Group:

```powershell
.\DataCollector.ps1 -GetEventLogs -Servers Agent1.contoso.com, Agent2.contoso.com, Agent3.contoso.com
```

To just gather the Event Logs from the Management Server(s) in the Management Group:

```powershell
.\DataCollector.ps1 -GetEventLogs
```


### Management Packs
To Export Installed Management Packs:

```powershell
.\DataCollector.ps1 -ExportMPs
```


### RunAs Accounts
To Export RunAs Accounts from the Management Server:

```powershell
.\DataCollector.ps1 -GetRunAsAccounts
```


### Check TLS 1.2 Readiness
To Run the TLS 1.2 Hardening Readiness Checks on every Management Server and SQL SCOM DB Server(s) in the Management Group:

```powershell
.\DataCollector.ps1 -CheckTLS
```

___

## MIT License

Copyright (c) 2024 Blake Drumm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
