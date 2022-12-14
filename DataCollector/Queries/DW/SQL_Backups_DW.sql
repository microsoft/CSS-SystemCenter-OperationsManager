SELECT 
	database_name AS [Database]
	, type AS BackupType
	, MAX(backup_start_date) AS LastBackupDate
	, GETDATE() AS CurrentDate
	, DATEDIFF(DD,MAX(backup_start_date),GETDATE()) AS DaysSinceBackup
FROM msdb.dbo.backupset BS WITH (NOLOCK) JOIN master.dbo.sysdatabases SD WITH (NOLOCK) ON BS.database_name = SD.[name]
GROUP BY database_name, type 
ORDER BY database_name, type