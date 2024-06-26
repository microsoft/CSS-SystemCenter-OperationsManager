# Script Version: v4.0.5

#### Last Updated: May 9, 2024 @ 2:28 AM

## Change Log

#### Additions
- Added ability to run extended latency checks. The built-in menu will ask you a question to confirm.
- Added spacing between the initial questions in the built-in menu.




---
&nbsp; \
&nbsp;

# Script Version: v4.0.4

#### Last Updated: May 8, 2024 @ 1:09 AM

## Change Log

#### Bug Fixes
- Fixed issue with TLS Checker function not displaying **True** for registry values that match `1`.




---
&nbsp; \
&nbsp;

# Script Version: v4.0.3

#### Last Updated: April 27, 2024 @ 10:55 AM

## Change Log

#### Additions
- Added TLS 1.3 support to TLS Checker.
- Updated internal version list for SCOM.

#### Bug Fixes
- Fixed bug with latency checker in General Information. All the servers weren't being checked as they should have been.




---
&nbsp; \
&nbsp;

# Script Version: v4.0.2

#### Last Updated: March 27, 2024 @ 6:06 PM

## Change Log

### Bug Fixes
- Fix issue with Best Practice Analyzer not using the correct file names for checking the RunAs Profiles and Group Membership Information.




---
&nbsp; \
&nbsp;
# Script Version: v4.0.1

#### Last Updated: March 27, 2024 @ 5:24 PM

## Change Log

### Bug Fixes
- Fix SQL Queries not executing on OpsDB due to new logic added. Reverted this change so all queries run as intended again.




---
&nbsp; \
&nbsp;
# Script Version: v4.0.0

#### Last Updated: March 25, 2024 @ 12:48 PM

## Change Log

### Bug Fixes
- Fixed Best Practice issues with detecting and comparing the DW Action Account, among other issues..
- Fixed a few small issues with Auto Updater script.
- Fixed Linux Data Collector gathering, everything is gathering as intended now!
- Fixed output of `MS_Information.txt` and added more information to it.
- Fixed the SCOM Port Checker function.

### Additions
- Added SQL Query to gather Local SQL Accounts from the OpsDB and DW SQL Instance(s). (`LocalSQLAccount_OpsDB.sql` and `LocalSQLAccount_DW.sql`)
- Added SQL Query to gather Agentless Servers. (`Agentless_Servers.sql`)
- Added new parameters: `-SCXMaintenanceUsername`, `-SCXMonitoringUsername`, `-ExportSCXCertificates`, `-ExportMSCertificates`, `-SCXWinRMEnumerateAllClasses`, `-SCXWinRMEnumerateSpecificClasses`, `-SCXResourcePoolDisplayName`, `-SCXUsername`, `-SCXWinRMCredentials`, and `-SkipBestPracticeAnalyzer`
- Added ability to detect if the version provided to the Product Version Function is an Azure Log Analytics Agent. This will show in the General Information text file.
- Gathering SCOM Groups via SQL Query.
- Updated the `Unix_Agents.sql` command to include the IsDeleted, TimeAdded, and LastModified columns.
- Added ability to gather the SCX Agent WinRM Query Results for: SCX_UnixProcess, SCX_Agent, SCX_OperatingSystem
- Updated the `Recently_Changed_*.sql` SQL Queries to be include data up to 180 days, instead of 4 days.




---
&nbsp; \
&nbsp;
# Script Version: v3.9.1

#### Last Updated: August 04, 2023 @ 8:38 PM

## Change Log

### Bug Fixes
- Fix issue with the Assemble script so that the Linux Data Collector function is now included in the release.
- Removed Event Log gathering, dependency on `Get-EventLog`.





---
&nbsp; \
&nbsp;
# Script Version: v3.9.0

#### Last Updated: July 25, 2023 @ 12:15 AM

## Change Log

### Additions
- Added new Operations Manager DB query to gather SCX Agent Logical Disk Instance Space count: `SCX_LogicalDiskInstanceSpaceCount.sql`
- Updated the internal product version list to be current.
- Added ability to detect IIS version.

### Bug Fixes
- Many issues fixed that caused PSScriptAnalyzer to fail on many items. Those have been resolved.
- Fix issue with displaying the SQL Edition for Operations Manager Database if there is an issue detected within the Best Practice Analyzer.
- Fixed issue with Linux Data Collector not automating the process of collection.
- Fixed .NET version showing twice in General Information.
- Added further checking for SQL Analysis in Best Practice Analyzer.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.18 (unreleased)

#### Last Updated: November 30, 2022 @ 8:00 AM

## Change Log

### Bug Fixes
- Many issues fixed that caused PSScriptAnalyzer to fail on many items. Those have been resolved.
- Fix issue with displaying the SQL Edition for Operations Manager Database if there is an issue detected within the Best Practice Analyzer.
- Fixed issue with Linux Data Collector not automating the process of collection.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.17

#### Last Updated: November 15, 2022 @ 3:44 PM

## Change Log

### Bug Fixes
- Fully remove `-AcceptEULA` from Data Collector.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.16

#### Last Updated: November 08, 2022 @ 7:44 PM

## Change Log

### Bug Fixes
- Remove the EULA from start of script, as it is causing issues running the script.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.15

#### Last Updated: November 04, 2022 @ 12:10 AM

## Change Log

### Additions
- Added Diagnostic Tools License/EULA to start of tool. You can bypass this by running `-AcceptEula` or `-ae`
- Added the following new SQL Queries: `DW_Alerts_ByDay.sql`, `DW_Alerts_ByCount.sql`, `DW_Alerts_ByRepeat.sql`, `DW_Alerts_ByOldest.sql`
- Added WinRM Configuration Details to the General Information text file.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.14

#### Last Updated: October 26, 2022 @ 2:22 AM

## Change Log

### Additions
- Added Resource Information to General Information.txt: CPU, Memory, Computer Model.
- Added Best Practice Analyzer - New check to make sure all SCOM SQL Database files are not located on the same physical drive.
- Added Best Practice Analyzer - New check for Enterprise and Standard edition of SQL Server for SCOM OpsDB and DW.
- Added Best Practice Analyzer - New check to verify the size of your SCOM SQL Databases are sufficient for optimal utilization.

### Bug Fixes
- Fixed `Get-TimeZone` error for older versions of Powershell.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.13

#### Last Updated: October 14, 2022 @ 6:58 PM

## Change Log

### Bug Fixes
- Fix issue with Data Warehouse Action account best practices checker.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.12

#### Last Updated: October 12, 2022 @ 8:01 PM

## Change Log

## Changes
- Updated the Start / End time to include time zone. Located in output zip: `datacollector-v3.8.12`





---
&nbsp; \
&nbsp;
# Script Version: v3.8.11

#### Last Updated: October 11, 2022 @ 10:05 PM

## Change Log

### Bug Fixes
- Fix issue with Best Practice Analyzer for SPN checking.
- Fix Connectivity Tester to ignore local server Invoke-Command ability.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.10

#### Last Updated: September 29, 2022 @ 5:56 AM

## Change Log

### Bug Fixes
- Fix some logical issues with Best Practice Analyzer.

### Additions
- Added Best Practice Analyzer - Data Warehouse Report Deployment Account RunAs Profile checking

## Changes
- Renamed `MG_ResourcePools.sql` to `ResourcePools.sql`
- Changed built-in menu for option 1. You will see a Note for the information not gathered with the `-All` switch *or* option **1**.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.9-3

#### Last Updated: September 27, 2022 @ 3:31 PM

## Change Log

### Bug Fixes
- Best Practice Analyzer - Fixed SPN Best Practice Detection.
- Best Practice Analyzer - Added much more information on how to resolve DW Writer mismatch.
- SQL Log Collection will now exclude: `*.MDMP, *.dmp, *.trc`

### Additions
- Added Best Practice Analyzer - Group Analyzer for dynamic groups with many expressions (more than 15).
- Added Powershell Group Policy information to General Information.
- New parameter switch `-GetUserRoles`
- Added FIPS to TLS Checker output.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.9-2

#### Last Updated: August 25, 2022 @ 2:55 AM

## Change Log

### Bug Fixes
- Fixed issue with the `-CheckTLS` parameter, which would show the TLS Checker output while running the data collector. This no longer happens.
- Fixed error handling in parameter: `-ExportMPs`

### Additions
- Added new SQL Query: `TaskStatus.sql`
- Added **Disk Allocation Unit Size** to `General Information.txt`.
- Added **.NET version** to `General Information.txt`.
- Updated the internal build list for SCOM, SSRS, and SQL.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.9-1

#### Last Updated: August 12, 2022 @ 10:51 PM

## Change Log

### Bug Fixes

- Many additions for Verbose Logging.
- Some tweaks to Best Practice Analyzer for SPN Data.
- Fixed bug with General Info.
- Many small fixes.

### Additions
- General Information will now output Service Information to a CSV: `OS_Services.csv`.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.9

#### Last Updated: August 12, 2022 @ 12:15 PM

## Change Log

### Bug Fixes

- Fix issue with gathering `-All` data from Agents via the Menu.
- Added better error handling to most options in the script.

### Additions

- Best Practice Analyzer is verifying the SPN information is correct.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.8

#### Last Updated: July 28, 2022 @ 11:45 AM

## Change Log

### Bug Fixes

- Fixed columns returned with User Rights Assignment (`-GetLocalSecurity`).

### Additions

- New condition being checked by the Best Practice Analyzer:
  - Will verify if there is an Operations Manager Event Id: **21410** present. If so, the script will guide you to increasing the Async Process Limit for the Command Notification Channel. More info: [https://kevinholman.com/2021/08/25/what-account-will-command-channel-notifications-run-as-in-scom/](https://kevinholman.com/2021/08/25/what-account-will-command-channel-notifications-run-as-in-scom/)






---
&nbsp; \
&nbsp;
# Script Version: v3.8.7

#### Last Updated: July 18, 2022 @ 3:39 PM

## Change Log

### Bug Fixes

- Fixed Latency checker Best Practice Analyzer.

### Additions

- Added TLS Cipher Suites to the `-CheckTLS` parameter.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.6

#### Last Updated: July 14, 2022 @ 11:41 AM

## Change Log

### Bug Fixes

- Fixed the `-MSInfo32` switch to allow it gather with the `-All` switch.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.5

#### Last Updated: June 28, 2022 @ 5:46 PM

## Change Log

### Bug Fixes

- Fixed DBSize Query for OperationsManager and Data Warehouse Databases.
- Modified the Grooming_Logs_OpsDB.sql query to not include `seconds` in the value field.


### Additions

- Added WinHTTP Proxy information to General Information.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.4

#### Last Updated: June 16, 2022 @ 2:13 AM

## Change Log

### Bug Fixes

- Fixed small issue with the `-GetConfiguration` switch.
- Fixed issue with Product Version Detection for SCOM 2022 Agent.
- Updated internal SCOM / SQL Build Version lists.

### Additions

- Modified `-GetConfiguration` switch to gather registry data on more paths:
  - `HKLM:\SYSTEM\CurrentControlSet\services\HealthService`
  - `HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0`
  - `HKLM:\SOFTWARE\Microsoft\System Center\2010`
  - `HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12`
- Added **User Roles**, so you will now get a full list of User Roles and their Members.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.3

#### Last Updated: June 07, 2022 @ 2:44 PM

## Change Log

### Bug Fixes

- Fixed All Menu Option, now will gather Configuration as originally intended.
- Local Security / User Rights will now collect again, there was a bug that has been fixed.
- Fixed alot of tiny bugs.
- Script will now run from Powershell ISE as intended.





---
&nbsp; \
&nbsp;
# Script Version: v3.8.2

#### Last Updated: April 05, 2022 @ 12:08 PM

## Change Log

### Bug Fixes

- Fix issue with Output Folder not being created when running the parameter `-SQLOnly`
- Added better error handling for select-object with OpsMgrAC registry key, when running `-CheckTLS`.
- Attempt to fix the output of the Best Practice Analyzer so that all detected items are not written to the same line.

### Additions

- Added new SQL Query: `Maintenance_Mode_ManagementServers.sql`

---
&nbsp; \
&nbsp;

## More Information

- The next big release will contain the Linux Data Collector (script developed by Udish Mudiar)! His script is located here: [https://github.com/Udish17/SCOMLinuxDataCollector](https://github.com/Udish17/SCOMLinuxDataCollector)





---
&nbsp; \
&nbsp;
# Script Version: v3.8.1

#### Last Updated: March 18, 2022 @ 5:05 PM

## Change Log

### Bug Fixes

- You will now get prompted everytime you run the script without a `-Yes` parameter, that asks you if you want to run the script as another account.
- Attempted to fix GpResult to allow it to return correctly.
- Fixed several small bugs in General Information.
- Attempt to fix error reporting to `Error.log`.
- Updated `-CheckTLS` it will now verify if you have OBDC Driver v11, 13, 17, or 18 installed.
- Updated `-GetRulesAndMonitors`, it will now return the correct data for Rules / Monitors where it would fail before.
- Fixed issue with `-GetLocalSecurity` not returning correctly for the local machine. Also attempted to add better error handling.
- Fixed issue with `-GetInstallLogs` where it would not correctly copy the files due to paths being invalid.
- `$ManagementServer` internal variable that would return incorrectly due to an issue with how I was calculating the correct server, this is now fixed.
- Configuration Checker has been fixed to work with the `-ManagementServers` parameter.
- Fixed issue when relaunching the script as another account, this was caused by the first question (Do you want to run as SDK?), this is now fixed and should no longer be an issue.
- Connectivity test to remote file shares should no longer fail if you are actually able to access them.
- Other small unlisted fixes.

### Additions

- Linux Agent Authentication Type has been added to `General Information.txt` (Kerberos / Basic) - <https://docs.microsoft.com/en-us/system-center/scom/manage-linux-kerberos-auth?view=sc-om-2019#enable-or-disable-kerberos-authentication-on-a-management-or-a-gateway-server>
- Updated script internal SQL Product version list to latest released.
- Added ability to output script runtime information into the version file that is in the output zip (`datacollector-v3.8.1` file).

    ```text
    Script Running as User:
    contoso\Administrator

    Script Running on Server:
    MS01-2019

    Script Path:
    C:\DataCollector\DataCollector.ps1

    Parameters Passed:
    -AssumeYes  -SkipConnectivityTests  -ManagementServers MS02-2019 

    Script execution started on date/time:
    March 18, 2022 @ 1:49 PM

    Script execution completed on date/time:
    March 18, 2022 @ 1:54 PM
    ```

- New Parameter `-SkipConnectivityTests`
- New Parameter `-SkipGeneralInformation`
- New Parameter `-SkipSQLQueries`
- New Script Auto Updater will be included. This will allow you to download the latest version of the Data Collector from the internet. (*Option 4* in the Built-in Menu **OR** the new file included in the release `Script-Auto-Updater.ps1`).
- Added System Uptime to General Information.
- Added w32tm gathering to the General Information text file, to assist with issues relating to time skew.
- Added Best Practice Anaylzer to Output of Script Execution.
- Added ability for Best Analyzer to be run against local and remote **Management Servers**.
- The Report Builder will be included in the Release Assets going forward.

---
&nbsp; \
&nbsp;

## More Information

- You now have more control over the Data Collector with the ability to skip checks / general information gathering.

    >## Example 1
    >
    >If you want to gather the Event Logs from all Management Servers and **THATS IT**:
    >
    >```powershell
    >.\DataCollector.ps1 -SkipSQLQueries -SkipGeneralInformation -GetEventLogs
    >```
    >
    >## Example 2
    >
    >If you want to skip connectivity checks and attempt to get **as much data as possible**:
    >
    >```powershell
    >.\DataCollector.ps1 -SkipConnectivityTests -All
    >

- The only gathering the script does by default when the script is run, is the `General Information.txt` file and the SQL Queries. But you can exclude these with the following parameters: `-SkipGeneralInformation -SkipSQLQueries`