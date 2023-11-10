declare @AgentVersionCol as nvarchar(max)
declare @ArchitectureCol as nvarchar(max)
declare @IPAddressCol as nvarchar(max)
declare @query as nvarchar(max)
SELECT @AgentVersionCol=COLUMN_NAME FROM INFORMATION_SCHEMA.Columns where TABLE_NAME = 'MT_Microsoft$Unix$Computer'
and COLUMN_NAME Like 'AgentVersion%'
SELECT @ArchitectureCol=COLUMN_NAME FROM INFORMATION_SCHEMA.Columns where TABLE_NAME = 'MT_Microsoft$Unix$Computer'
and COLUMN_NAME Like 'Architecture%'
SELECT @IPAddressCol=COLUMN_NAME FROM INFORMATION_SCHEMA.Columns WHERE TABLE_NAME = 'MT_Microsoft$Unix$Computer'
AND COLUMN_NAME Like 'IPAddress%'
set @query = 'select bme2.fullname as ''FullName'', bme2.Displayname as ''DisplayName'', ' + @AgentVersionCol + '  as ''Build'' ,
' + @ArchitectureCol + ' as ''Architecture'', ' + @IPAddressCol + ' as ''IPAddress'', bme.Displayname as ''ResourcePool'', bme.IsDeleted, bme.TimeAdded, bme.LastModified
from dbo.Relationship r with (nolock) 
LEFT join dbo.RelationshipType rt with (nolock) 
on r.RelationshipTypeId = rt.RelationshipTypeId 
LEFT join dbo.BasemanagedEntity bme with (nolock) 
on bme.basemanagedentityid = r.SourceEntityId 
LEFT join dbo.BasemanagedEntity bme2 with (nolock) 
on r.TargetEntityId = bme2.BaseManagedEntityId 
LEFT join MT_Microsoft$Unix$Computer mtvc
on bme2.BaseManagedEntityId = mtvc.BaseManagedEntityId
where rt.RelationshipTypeName = ''Microsoft.SystemCenter.ManagementActionPointManagesEntity ''  
and r.IsDeleted = 0 
and bme2.basemanagedtypeid in (SELECT DerivedTypeId 
FROM DerivedManagedTypes with (nolock) 
WHERE BaseTypeId = (select managedtypeid 
from managedtype where typename = ''Microsoft.Unix.Computer'') 
and DerivedIsAbstract = 0)
ORDER BY DisplayName DESC'
exec(@query)
