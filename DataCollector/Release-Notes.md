# Change Log

## Bug Fixes
- Fixed Best Practice issues with detecting and comparing the DW Action Account, among other issues..
- Fixed a few small issues with Auto Updater script.
- Fixed Linux Data Collector gathering, everything is gathering as intended now!
- Fixed output of `MS_Information.txt` and added more information to it.
- Fixed the SCOM Port Checker function.

## Additions
- Added SQL Query to gather Local SQL Accounts from the OpsDB and DW SQL Instance(s). (`LocalSQLAccount_OpsDB.sql` and `LocalSQLAccount_DW.sql`)
- Added SQL Query to gather Agentless Servers. (`Agentless_Servers.sql`)
- Added new parameters: `-SCXMaintenanceUsername`, `-SCXMonitoringUsername`, `-ExportSCXCertificates`, `-ExportMSCertificates`, `-SCXWinRMEnumerateAllClasses`, `-SCXWinRMEnumerateSpecificClasses`, `-SCXResourcePoolDisplayName`, `-SCXUsername`, `-SCXWinRMCredentials`, and `-SkipBestPracticeAnalyzer`
- Added ability to detect if the version provided to the Product Version Function is an Azure Log Analytics Agent. This will show in the General Information text file.
- Gathering SCOM Groups via SQL Query.
- Updated the `Unix_Agents.sql` command to include the IsDeleted, TimeAdded, and LastModified columns.
- Added ability to gather the SCX Agent WinRM Query Results for: SCX_UnixProcess, SCX_Agent, SCX_OperatingSystem
- Updated the `Recently_Changed_*.sql` SQL Queries to be include data up to 180 days, instead of 4 days.