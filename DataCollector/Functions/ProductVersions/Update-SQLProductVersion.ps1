# Add the necessary .NET assembly for URL encoding
Add-Type -AssemblyName System.Web

# Define the SQL query
$Query = "select *"

# Build the full URL including the encoded query
$EncodedQuery = [System.Web.HttpUtility]::UrlEncode($Query)
$URL = "https://docs.google.com/spreadsheets/d/16Ymdz80xlCzb6CwRFVokwo0onkofVYFoSkc7mYe6pgw/gviz/tq?tq=$EncodedQuery&tqx=out:csv"

# Use Invoke-WebRequest to download the CSV content
$WebResponse = Invoke-WebRequest -Uri $URL

# Convert the content to a CSV object
$SQLServer = $WebResponse.Content | ConvertFrom-Csv

# Initialize an array to hold the final output
$finaloutput = @()

# Process each row of the CSV
foreach ($data in $SQLServer) {
    # Check if the CSV contains the expected headers
    if ($data.PSObject.Properties.Name -contains 'Build' -and
        $data.PSObject.Properties.Name -contains 'Description' -and
        $data.PSObject.Properties.Name -contains 'ReleaseDate') {
        
        # Escape single quotes for SQL compatibility, remove new lines, and replace en dash with hyphen
        $description = $data.Description -Replace '"', '""' -Replace "`n", '' -Replace "–", '-'
        $build = $data.Build -Replace '"', '""'
        $releaseDate = $data.ReleaseDate -Replace '"', '""'
        
        # Construct a formatted string for each row
        $formattedString = "`"{0}`" {{ `"{1} / {2}`" }}" -f $build, (Get-Culture).TextInfo.ToTitleCase($description), $releaseDate

        # Add the formatted string to the final output array
        $finaloutput += $formattedString
    }
    else {
        Write-Host "CSV data does not contain the expected headers." -ForegroundColor Red
    }
}

# Output the final result to the host and copy to the clipboard
Write-Host "Copied to Clipboard!" -ForegroundColor Green
Set-Clipboard -Value ($finaloutput -join "`n")

# Display the final output
$finaloutput
