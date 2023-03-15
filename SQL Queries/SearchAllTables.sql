/****** Object:  StoredProcedure [dbo].[SearchAllTables]    Script Date: 04/06/2009 22:59:52 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
--EXEC SearchAllTables '8510EC59-EB20-4310-988B-3876B4F7CD39'
--GO 

--Here is the complete stored procedure code: 


CREATE PROC [dbo].[SearchAllTables]
(
                @SearchStr nvarchar(100)
)
AS
BEGIN

                -- Copyright © 2002 Narayana Vyas Kondreddi. All rights reserved.
                -- Purpose: To search all columns of all tables for a given search string
                -- Written by: Narayana Vyas Kondreddi
                -- Site: http://vyaskn.tripod.com
                -- Tested on: SQL Server 7.0 and SQL Server 2000
                -- Date modified: 28th July 2002 22:50 GMT


                CREATE TABLE #Results (ColumnName nvarchar(370), ColumnValue nvarchar(3630))

                SET NOCOUNT ON

                DECLARE @TableName nvarchar(256), @ColumnName nvarchar(128), @SearchStr2 nvarchar(110)
                SET  @TableName = ''
                SET @SearchStr2 = QUOTENAME('%' + @SearchStr + '%','''')

                WHILE @TableName IS NOT NULL
                BEGIN
                                SET @ColumnName = ''
                                SET @TableName = 
                                (
                                                SELECT MIN(QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME))
                                                FROM   INFORMATION_SCHEMA.TABLES
                                                WHERE                                 TABLE_TYPE = 'BASE TABLE'
                                                                AND       QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME) > @TableName
                                                                AND       OBJECTPROPERTY(
                                                                                                OBJECT_ID(
                                                                                                                QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME)
                                                                                                                 ), 'IsMSShipped'
                                                                                                       ) = 0
                                )

                                WHILE (@TableName IS NOT NULL) AND (@ColumnName IS NOT NULL)
                                BEGIN
                                                SET @ColumnName =
                                                (
                                                                SELECT MIN(QUOTENAME(COLUMN_NAME))
                                                                FROM   INFORMATION_SCHEMA.COLUMNS
                                                                WHERE                                 TABLE_SCHEMA               = PARSENAME(@TableName, 2)
                                                                                AND       TABLE_NAME    = PARSENAME(@TableName, 1)
                                                                                AND       DATA_TYPE IN ('char', 'varchar', 'nchar', 'nvarchar', 'uniqueidentifier')
                                                                                AND       QUOTENAME(COLUMN_NAME) > @ColumnName
                                                )
                
                                                IF @ColumnName IS NOT NULL
                                                BEGIN
                                                                INSERT INTO #Results
                                                                EXEC
                                                                (
                                                                                'SELECT ''' + @TableName + '.' + @ColumnName + ''', LEFT(' + @ColumnName + ', 3630) 
                                                                                FROM ' + @TableName + ' (NOLOCK) ' +
                                                                                ' WHERE ' + @ColumnName + ' LIKE ' + @SearchStr2
                                                
                                                                )
                                                                --Print @TableName
                                                END
                                END       
                END

                SELECT ColumnName, ColumnValue FROM #Results
END
