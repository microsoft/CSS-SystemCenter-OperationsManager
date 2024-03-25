SELECT DISTINCT
    Profile.Name AS ProfileName,
	Profile.DisplayName AS ProfileDisplayName,
    CASE SecureData.[Type]
        WHEN 0 THEN 'SNMPv3 Account'
        WHEN 1 THEN 'Action Account'
        WHEN 2 THEN 'Windows'
        WHEN 3 THEN 'Simple Authentication'
        WHEN 4 THEN 'Basic Authentication'
        WHEN 5 THEN 'Digest Authentication'
        WHEN 6 THEN 'Community String'
        WHEN 7 THEN 'Binary Authentication'
    END AS CredentialType,
    SecureData.[Name] AS CredentialName,
    SecureData.[Description] AS CredentialDescription,
    SecureData.[Domain] AS CredentialDomain,
    SecureData.[UserName] AS CredentialUserName,
    SecureData.[LastModified] AS CredentialLastModified,
    REPLACE(REPLACE(SecureData.[IsSystem], 0, 'False'), 1, 'True') AS IsSystem,
    SecureData.[AssemblyQualifiedName],
    SecureData.[Id] AS CredentialId,
    SecureData.[SecureStorageId],
    SecureData.[ConfigurationXml],
    [Override].OverrideName,
    [Override].Value AS SSID,
    bme.FullName AS EntityFullName,
    mt.TypeName AS ManagedTypeName
FROM 
    dbo.fn_CredentialManagerStoreByCriteriaWithoutSecretDataView(N'ENU', N'ENU') AS SecureData
LEFT JOIN 
    CredentialManagerSecureStorageView AS Account
    ON SecureData.SecureStorageId = Account.SecureStorageId
LEFT JOIN 
    SecureReferenceOverride AS [Override] WITH (NOLOCK)
    ON CONVERT(varchar(80), Account.SecureStorageId, 2) = [Override].Value
LEFT JOIN 
    SecureReferenceView AS Profile WITH (NOLOCK)
    ON [Override].SecureReferenceId = Profile.Id
LEFT JOIN
    ManagedType mt WITH (NOLOCK)
    ON [Override].TypeContext = mt.ManagedTypeId
LEFT JOIN 
    BaseManagedEntity bme WITH (NOLOCK)
    ON [Override].InstanceContext = bme.BaseManagedEntityId
ORDER BY 
    ProfileName, CredentialType, CredentialName
