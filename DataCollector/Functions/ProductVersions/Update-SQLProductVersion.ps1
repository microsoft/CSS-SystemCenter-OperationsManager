Add-Type -Assembly System.Web # [System.Web.HttpUtility]::UrlEncode() needs this

$Query = "select *"
$URL   = "https://docs.google.com/spreadsheets/d/16Ymdz80xlCzb6CwRFVokwo0onkofVYFoSkc7mYe6pgw/gviz/tq?tq=" `
       + [System.Web.HttpUtility]::UrlEncode($Query) `
       + "&tqx=out:csv"

Invoke-WebRequest $URL -OutFile "C:\Temp\SqlServerBuilds.csv"
$SQLServer = Import-CSV -Path "C:\Temp\SqlServerBuilds.csv"

$finaloutput = @()
foreach($data in $SQLServer)
{
$description = $data.Description -Replace('"',"'")
$finaloutput += ("`~{0}`~ !.! `~{1} / {2}`~ !!!" -f $data.Build, (Get-Culture).TextInfo.ToTitleCase($description.Replace("`n",'')), $data.ReleaseDate).Replace("!.!","{").Replace("!!!","}").Replace("~",'"').Replace("`n",'')
}
Write-Host "Copied to Clipboard!" -ForegroundColor Green
Set-Clipboard -Value $finaloutput
$finaloutput