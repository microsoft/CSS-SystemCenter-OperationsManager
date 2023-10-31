/*
==================================================================================================
Script Title: Configuration Script for MaxDOP and Cost Threshold for Parallelism
Author: Blake Drumm
Date: 2023-10-30
Description: 
    This script is designed to review and recommend settings for MaxDOP and Cost Threshold for
    Parallelism for SQL Server in a System Center Operations Manager (SCOM) environment.
    It checks the current configuration, calculates recommended values based on the system's 
    hardware and existing settings, and generates a script for applying the recommended settings.

Usage:
    1. Customize the @RecommendedCostThreshold variable if a value within the range of 40-50 is desired.
    2. Run the script in a SQL Server Management Studio (SSMS) query window connected to the target
       SQL Server instance.
    3. Review the results and execute the generated script if the recommended settings are acceptable.

Revision History:
    2023-10-31: Script modified by Blake Drumm
    2023-10-30: Script created by Blake Drumm
==================================================================================================
*/

SET NOCOUNT ON;
USE MASTER;

-- Declare variables
DECLARE @NumaNodes INT,
        @NumCPUs INT,
        @MaxDop INT,
        @RecommendedMaxDop INT,
        @CostThreshold INT,
        @RecommendedCostThreshold VARCHAR(5) = '40-50',
        @ChangeScript NVARCHAR(MAX) = '',
        @ShowAdvancedOptions INT,
        @TempDBFileCount INT;

-- Getting number of NUMA nodes
SELECT @NumaNodes = COUNT(DISTINCT parent_node_id) FROM sys.dm_os_schedulers WHERE status = 'VISIBLE ONLINE';

-- Getting number of CPUs (cores)
SELECT @NumCPUs = cpu_count FROM sys.dm_os_sys_info;

-- Getting current MAXDOP at instance level
SELECT @MaxDop = CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'max degree of parallelism';

-- Getting current Cost Threshold for Parallelism
SELECT @CostThreshold = CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'cost threshold for parallelism';

-- Check 'show advanced options' setting
SELECT @ShowAdvancedOptions = CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'show advanced options';

-- Get the number of TempDB data files
SELECT @TempDBFileCount = COUNT(*) FROM sys.master_files WHERE database_id = DB_ID('TempDB') AND type = 0;

-- MAXDOP Calculation
IF @NumaNodes = 1
BEGIN
    IF @NumCPUs < 8
        SET @RecommendedMaxDop = @NumCPUs;
    ELSE
        SET @RecommendedMaxDop = 8;
END
ELSE
BEGIN
    IF (@NumCPUs / @NumaNodes) < 8
        SET @RecommendedMaxDop = (@NumCPUs / @NumaNodes);
    ELSE
        SET @RecommendedMaxDop = 8;
END

-- Define a table variable to store the results
DECLARE @Results TABLE (Description NVARCHAR(255), Value NVARCHAR(255));

-- Insert existing settings and recommendations into @Results
INSERT INTO @Results (Description, Value)
VALUES ('MAXDOP Configured Value', CAST(@MaxDop AS VARCHAR)),
       ('MAXDOP Recommended Value', CAST(@RecommendedMaxDop AS VARCHAR)),
       ('Cost Threshold Configured Value', CAST(@CostThreshold AS VARCHAR)),
       ('Generally Recommended Cost Threshold', @RecommendedCostThreshold),
       ('Current TempDB Data Files Count', CAST(@TempDBFileCount AS VARCHAR)),
       ('TempDB Data Files Recommended Count', CAST(@RecommendedMaxDop AS VARCHAR));

-- TempDB data files recommendation
IF @TempDBFileCount != @RecommendedMaxDop
BEGIN
    INSERT INTO @Results (Description, Value)
    VALUES ('TempDB Data Files Recommendation', 'The number of TempDB data files does not match the recommended MAXDOP setting. Consider changing it.');
    
    SET @ChangeScript = @ChangeScript + 'ALTER DATABASE TempDB MODIFY FILE (NAME = ' + (SELECT name FROM sys.master_files WHERE database_id = DB_ID('TempDB') AND type = 0) + ', FILEGROWTH = 512MB);';
    
    INSERT INTO @Results (Description, Value)
    VALUES ('TempDB File Adjustment Script', @ChangeScript);
END

-- Check and build ChangeScript for other settings
IF @ShowAdvancedOptions <> 1
    SET @ChangeScript = @ChangeScript + 'EXEC sp_configure ''show advanced options'', 1; RECONFIGURE WITH OVERRIDE; ';

IF @MaxDop <> @RecommendedMaxDop
    SET @ChangeScript = @ChangeScript + 'EXEC sp_configure ''max degree of parallelism'', ' + CAST(@RecommendedMaxDop AS VARCHAR) + '; RECONFIGURE WITH OVERRIDE; ';

IF @CostThreshold < 40 OR @CostThreshold > 50
    SET @ChangeScript = @ChangeScript + 'EXEC sp_configure ''cost threshold for parallelism'', 45; RECONFIGURE WITH OVERRIDE; ';

-- Insert the "Change Script" row only if there are changes to be made
IF LEN(@ChangeScript) > 0
    INSERT INTO @Results (Description, Value)
    VALUES ('Change Script', @ChangeScript);

-- Display the results
SELECT * FROM @Results;
