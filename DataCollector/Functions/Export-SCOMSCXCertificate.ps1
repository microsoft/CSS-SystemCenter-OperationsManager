function Export-SCXCertificate {
    [cmdletbinding()]
    param (
        [string]$OutputDirectory = "C:\Temp\SCXCertificates",
        [array]$ComputerName = $env:COMPUTERNAME
    )

    # Ensure the base output directory exists
    if (-not (Test-Path -Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    # Script block to execute on each machine to export the SCX certificate
    $scriptBlock = {
        Get-ChildItem "Cert:\LocalMachine\Root\" | Where-Object { $_.DnsNameList.Unicode -contains "SCX-Certificate" } | ForEach-Object {
            $CertificateIssuer = if ($_.Issuer -match 'DC=(?<DomainComponent>[^,]+)') {
                $matches['DomainComponent']
            } else {
                'UnknownIssuer'
            }
            $FileName = "$CertificateIssuer.cer"
            # Output the filename and raw data
            [PSCustomObject]@{
                FileName = $FileName
                RawData = $_.RawData
            }
        }
    }

    foreach ($Computer in $ComputerName) {
        Write-Verbose "$(Invoke-TimeStamp)Gathering SCOM SCX Certificates from $Computer"
        # Define the output directory for the current computer
        $currentOutputDirectory = Join-Path -Path $OutputDirectory -ChildPath $Computer

        # Ensure the output directory for the current computer exists
        if (-not (Test-Path -Path $currentOutputDirectory)) {
            New-Item -Path $currentOutputDirectory -ItemType Directory -Force | Out-Null
        }

        # Collect the certificate data from the remote computer
        $certData = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock

        # Write the raw data to certificate files in the local computer's directory
        foreach ($cert in $certData) {
            $localFilePath = Join-Path -Path $currentOutputDirectory -ChildPath $cert.FileName
            Set-Content -Path $localFilePath -Value $cert.RawData -Encoding Byte
        }
        Write-Verbose "$(Invoke-TimeStamp)Completed gathering SCOM SCX Certificates from $Computer"
    }
}