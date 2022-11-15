DECLARE @RelationshipTypeId_Manages UNIQUEIDENTIFIER 
SELECT @RelationshipTypeId_Manages = dbo.fn_RelationshipTypeId_Manages() 
SELECT TOP 500 bme.DisplayName, SUM(1) AS HostedInstances, dt.TypedEntityName, dt.BMEPath
FROM BaseManagedEntity bme WITH (NOLOCK)
RIGHT JOIN ( 
SELECT 
      HBME.BaseManagedEntityId AS HS_BMEID, 
      TBME.FullName AS TopLevelEntityName, 
      BME.FullName AS BaseEntityName, 
      TYPE.TypeName AS TypedEntityName,
	BME.Path AS BMEPath
FROM BaseManagedEntity BME WITH(NOLOCK) 
      INNER JOIN TypedManagedEntity TME WITH(NOLOCK) ON BME.BaseManagedEntityId = TME.BaseManagedEntityId AND BME.IsDeleted = 0 AND TME.IsDeleted = 0 
      INNER JOIN BaseManagedEntity TBME WITH(NOLOCK) ON BME.TopLevelHostEntityId = TBME.BaseManagedEntityId AND TBME.IsDeleted = 0 
      INNER JOIN ManagedType TYPE WITH(NOLOCK) ON TME.ManagedTypeID = TYPE.ManagedTypeID 
      LEFT JOIN Relationship R WITH(NOLOCK) ON R.TargetEntityId = TBME.BaseManagedEntityId AND R.RelationshipTypeId = @RelationshipTypeId_Manages AND R.IsDeleted = 0 
      LEFT JOIN BaseManagedEntity HBME WITH(NOLOCK) ON R.SourceEntityId = HBME.BaseManagedEntityId 
) AS dt ON dt.HS_BMEID = bme.BaseManagedEntityId 
GROUP by BME.displayname, dt.TypedEntityName, dt.BMEPath
order by HostedInstances DESC