#Requires -RunAsAdministrator
#Requires -Modules WebAdministration

# Load System.Web assembly for HttpUtility
Add-Type -AssemblyName System.Web

# Initialize HTML report
$htmlReport = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>IIS CIS Benchmark Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .pass { color: green; }
        .fail { color: red; }
        .manual { color: orange; }
        .na { color: gray; }
    </style>
</head>
<body>
    <h1>IIS CIS Benchmark Audit Report</h1>
    <p>Generated on: $(Get-Date)</p>
"@

# Function to add check result to HTML report
function Add-CheckResult {
    param (
        [string]$Section,
        [string]$CheckName,
        [string]$Status,
        [string]$Details
    )
    $script:htmlReport += @"
    <h2>$Section</h2>
    <table>
        <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Details</th>
        </tr>
        <tr>
            <td>$CheckName</td>
            <td class='$($Status.ToLower())'>$Status</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($Details))</td>
        </tr>
    </table>
"@
}

# Function to check if output indicates compliance
function Test-Compliance {
    param (
        [string]$CheckId,
        [object]$Output,
        [string]$Expected
    )
    if ($null -eq $Output) {
        return "Not Available"
    }
    switch ($CheckId) {
        "1.3" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "1.4" {
            if ($Output.identityType -ne "LocalSystem") { return "Pass" } else { return "Fail" }
        }
        "1.6" {
            if ($Output.enabled -eq $true) { return "Pass" } else { return "Fail" }
        }
        "1.7" {
            if ($Output.State -eq "Absent") { return "Pass" } else { return "Fail" }
        }
        "2.3" {
            if ($Output.Value -eq $true) { return "Pass" } else { return "Fail" }
        }
        "2.4" {
            if ($Output.Value -eq "UseCookies") { return "Pass" } else { return "Fail" }
        }
        "2.5" {
            if ($Output.Value -eq "All") { return "Pass" } else { return "Fail" }
        }
        "2.6" {
            if ($Output.Value -like "*SSL*") { return "Pass" } else { return "Fail" }
        }
        "2.7" {
            if ($Output.Value -ne "Clear") { return "Pass" } else { return "Fail" }
        }
        "3.2" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "3.3" {
            if ($Output.Value -ne "Off") { return "Pass" } else { return "Fail" }
        }
        "3.4" {
            if ($Output.Value -eq "DetailedLocalOnly") { return "Pass" } else { return "Fail" }
        }
        "3.5" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "3.6" {
            if ($Output.Value -eq "InProc") { return "Pass" } else { return "Fail" }
        }
        "3.10" {
            if ($Output.Value -eq "Medium") { return "Pass" } else { return "Fail" }
        }
        "3.12" {
            if ($Output.Value -eq $true) { return "Pass" } else { return "Fail" }
        }
        "4.1" {
            if ($Output.Value -le 30000000) { return "Pass" } else { return "Fail" }
        }
        "4.2" {
            if ($Output.Value -le 4096) { return "Pass" } else { return "Fail" }
        }
        "4.3" {
            if ($Output.Value -le 2048) { return "Pass" } else { return "Fail" }
        }
        "4.4" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "4.5" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "4.7" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "4.8" {
            if ($Output.Value -notlike "*Write*") { return "Pass" } else { return "Fail" }
        }
        "4.9" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "4.10" {
            if ($Output.Value -eq $false) { return "Pass" } else { return "Fail" }
        }
        "4.11" {
            if ($Output.enabled -eq $true -and $Output.maxConcurrentRequests -le 10) { return "Pass" } else { return "Fail" }
        }
        "5.1" {
            if ($Output.Value -notlike "*inetpub*") { return "Pass" } else { return "Fail" }
        }
        "6.1" {
            if ($Output.controlChannelPolicy -eq "SslRequire" -and $Output.dataChannelPolicy -eq "SslRequire") { return "Pass" } else { return "Fail" }
        }
        "6.2" {
            if ($Output.Value -eq $true) { return "Pass" } else { return "Fail" }
        }
        "7.2" {
            if ($Output.Enabled -eq 0 -and $Output.DisabledByDefault -eq 1) { return "Pass" } else { return "Fail" }
        }
        "7.3" {
            if ($Output.Enabled -eq 0 -and $Output.DisabledByDefault -eq 1) { return "Pass" } else { return "Fail" }
        }
        "7.4" {
            if ($Output.Enabled -eq 0 -and $Output.DisabledByDefault -eq 1) { return "Pass" } else { return "Fail" }
        }
        "7.5" {
            if ($Output.Enabled -eq 0 -and $Output.DisabledByDefault -eq 1) { return "Pass" } else { return "Fail" }
        }
        "7.6" {
            if ($Output.Enabled -eq 1 -and $Output.DisabledByDefault -eq 0) { return "Pass" } else { return "Fail" }
        }
        "7.7" {
            if ($Output.Enabled -eq 0) { return "Pass" } else { return "Fail" }
        }
        "7.8" {
            if ($Output.Enabled -eq 0) { return "Pass" } else { return "Fail" }
        }
        "7.9" {
            if ($Output.Enabled -eq 0) { return "Pass" } else { return "Fail" }
        }
        "7.10" {
            if ($Output.Enabled -eq 0) { return "Pass" } else { return "Fail" }
        }
        "7.11" {
            if ($Output.Enabled -eq 1) { return "Pass" } else { return "Fail" }
        }
        "7.12" {
            if ($Output.Functions -match "TLS_ECDHE.*AES_256") { return "Pass" } else { return "Fail" }
        }
        default { return "Manual" }
    }
}

# Check if ServerManager module is available for Get-WindowsFeature
$serverManagerAvailable = Get-Module -ListAvailable -Name ServerManager

# 1. Basic Configuration Benchmark Audit
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.1 Ensure Web content is on non-system partition (Manual)" -Status "Manual" -Details (Get-Website | Format-List Name, PhysicalPath | Out-String)
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.2 Ensure Host headers are on all sites (Automated)" -Status "Manual" -Details (Get-WebBinding -Port * | Format-List bindingInformation | Out-String)
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.3 Ensure Directory browsing is set to Disabled (Automated)" -Status (Test-Compliance -CheckId "1.3" -Output (Get-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis: -Name Enabled)) -Details (Get-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis: -Name Enabled | Format-List Value | Out-String)
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.4 Ensure application pool identity is configured for all application pools (Automated)" -Status (Test-Compliance -CheckId "1.4" -Output (Get-ChildItem -Path IIS:AppPools | Select-Object name, state, @{e={$_.processModel.identityType};l="identityType"})) -Details (Get-ChildItem -Path IIS:AppPools | Select-Object name, state, @{e={$_.processModel.identityType};l="identityType"} | Format-List | Out-String)
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.5 Ensure unique application pools is set for sites (Automated)" -Status "Manual" -Details (Get-Website | Select-Object Name, applicationPool | Format-List | Out-String)
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.6 Ensure application pool identity is configured for anonymous user identity (Automated)" -Status (Test-Compliance -CheckId "1.6" -Output (Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -Recurse | Where-Object {$_.enabled -eq $true})) -Details (Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -Recurse | Where-Object {$_.enabled -eq $true} | Format-List location | Out-String)
Add-CheckResult -Section "1. Basic Configuration" -CheckName "1.7 Ensure WebDav feature is disabled (Automated)" -Status $(if ($serverManagerAvailable) { Test-Compliance -CheckId "1.7" -Output (Get-WindowsFeature Web-DAV-Publishing) } else { "Not Available" }) -Details $(if ($serverManagerAvailable) { Get-WindowsFeature Web-DAV-Publishing | Format-List Name, Installed | Out-String } else { "ServerManager module not available; cannot check WebDAV status. This feature is only available on Windows Server." })

# 2. Configuration Authentication and Authorization
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.1 Ensure global authorization rule is set to restrict access (Manual)" -Status "Manual" -Details (Get-WebConfiguration -pspath 'IIS:' -filter 'system.webServer/security/authorization' | Format-List | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.2 Ensure access to sensitive site features is restricted to authenticated principals only (Manual)" -Status "Manual" -Details (Get-WebConfiguration system.webServer/security/authentication/* -Recurse | Where-Object {$_.enabled -eq $true} | Format-Table | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.3 Ensure forms authentication require SSL (Manual)" -Status (Test-Compliance -CheckId "2.3" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'requireSSL')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table Name, Value | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.4 Ensure forms authentication is set to use cookies (Manual)" -Status (Test-Compliance -CheckId "2.4" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'cookieless')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'cookieless' | Format-List | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.5 Ensure cookie protection mode is configured for forms authentication (Manual)" -Status (Test-Compliance -CheckId "2.5" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'protection')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'protection' | Format-List | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.6 Ensure transport layer security for basic authentication is configured (Automated)" -Status (Test-Compliance -CheckId "2.6" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.webServer/security/access' -name 'sslFlags')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.webServer/security/access' -name 'sslFlags' | Format-List | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.7 Ensure passwordFormat is not set to clear (Manual)" -Status (Test-Compliance -CheckId "2.7" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' | Format-List | Out-String)
Add-CheckResult -Section "2. Authentication and Authorization" -CheckName "2.8 Ensure credentials are not stored in configuration files (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"

# 3. ASP.NET Configuration
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.1 Ensure deployment method retail is set (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.2 Ensure debug is turned off (Manual)" -Status (Test-Compliance -CheckId "3.2" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/compilation' -name 'debug')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/compilation' -name 'debug' | Format-List Name, Value | Out-String)
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.3 Ensure custom error messages are not off (Manual)" -Status (Test-Compliance -CheckId "3.3" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/customErrors' -name 'mode')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/customErrors' -name 'mode' | Format-List | Out-String)
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.4 Ensure IIS HTTP detailed errors are hidden from displaying remotely (Manual)" -Status (Test-Compliance -CheckId "3.4" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.webServer/httpErrors' -name 'errorMode')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.webServer/httpErrors' -name 'errorMode' | Format-List | Out-String)
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.5 Ensure ASP.NET stack tracing is not enabled (Manual)" -Status (Test-Compliance -CheckId "3.5" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/trace' -name 'enabled')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/trace' -name 'enabled' | Format-List Name, Value | Out-String)
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.6 Ensure httpcookie mode is configured for session state (Manual)" -Status (Test-Compliance -CheckId "3.6" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/sessionState' -name 'mode')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/sessionState' -name 'mode' | Format-List | Out-String)
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.7 Ensure cookies are set with HttpOnly attribute (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.8 Ensure MachineKey validation method - .Net 3.5 is configured (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.9 Ensure MachineKey validation method - .Net 4.5 is configured (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.10 Ensure global .NET trust level is configured (Manual)" -Status (Test-Compliance -CheckId "3.10" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/trust' -name 'level')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/trust' -name 'level' | Format-List | Out-String)
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.11 Ensure X-Powered-By Header is removed (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "3. ASP.NET Configuration" -CheckName "3.12 Ensure Server Header is removed (Manual)" -Status (Test-Compliance -CheckId "3.12" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'removeServerHeader')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'removeServerHeader' | Format-List | Out-String)

# 4. Request Filtering and Other Restriction Modules
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.1 Ensure maxAllowedContentLength is configured (Manual)" -Status (Test-Compliance -CheckId "4.1" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/requestLimits' -name 'maxAllowedContentLength')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/requestLimits' -name 'maxAllowedContentLength' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.2 Ensure maxURL request filter is configured (Automated)" -Status (Test-Compliance -CheckId "4.2" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/requestLimits' -name 'maxUrl')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/requestLimits' -name 'maxUrl' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.3 Ensure MaxQueryString request filter is configured (Automated)" -Status (Test-Compliance -CheckId "4.3" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/requestLimits' -name 'maxQueryString')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/requestLimits' -name 'maxQueryString' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.4 Ensure non-ASCII characters in URLs are not allowed (Automated)" -Status (Test-Compliance -CheckId "4.4" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.5 Ensure Double-Encoded requests will be rejected (Automated)" -Status (Test-Compliance -CheckId "4.5" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowDoubleEscaping')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowDoubleEscaping' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.6 Ensure HTTP Trace Method is disabled (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.7 Ensure Unlisted File Extensions are not allowed (Automated)" -Status (Test-Compliance -CheckId "4.7" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/fileExtensions' -name 'allowUnlisted')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering/fileExtensions' -name 'allowUnlisted' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.8 Ensure Handler is not granted Write and Script/Execute (Manual)" -Status (Test-Compliance -CheckId "4.8" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/handlers' -name 'accessPolicy')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/handlers' -name 'accessPolicy' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.9 Ensure notListedIsapisAllowed is set to false (Automated)" -Status (Test-Compliance -CheckId "4.9" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/isapiCgiRestriction' -name 'notListedIsapisAllowed')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/isapiCgiRestriction' -name 'notListedIsapisAllowed' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.10 Ensure notListedCgisAllowed is set to false (Automated)" -Status (Test-Compliance -CheckId "4.10" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/isapiCgiRestriction' -name 'notListedCgisAllowed')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/isapiCgiRestriction' -name 'notListedCgisAllowed' | Format-List | Out-String)
Add-CheckResult -Section "4. Request Filtering" -CheckName "4.11 Ensure Dynamic IP Address Restrictions is enabled (Manual)" -Status (Test-Compliance -CheckId "4.11" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests' -name 'enabled', 'maxConcurrentRequests')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests' -name 'enabled', 'maxConcurrentRequests' | Format-List | Out-String)

# 5. IIS Logging Recommendations
Add-CheckResult -Section "5. IIS Logging" -CheckName "5.1 Ensure Default IIS web log location is moved (Automated)" -Status (Test-Compliance -CheckId "5.1" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/logFile' -name 'directory')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/logFile' -name 'directory' | Format-List | Out-String)
Add-CheckResult -Section "5. IIS Logging" -CheckName "5.2 Ensure Advanced IIS logging is enabled (Automated)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "5. IIS Logging" -CheckName "5.3 Ensure ETW Logging is enabled (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"

# 6. FTP Request Benchmark
Add-CheckResult -Section "6. FTP Request" -CheckName "6.1 Ensure FTP requests are encrypted (Manual)" -Status (Test-Compliance -CheckId "6.1" -Output ([PSCustomObject]@{
    controlChannelPolicy = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -name 'controlChannelPolicy').Value
    dataChannelPolicy = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -name 'dataChannelPolicy').Value
})) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -name 'controlChannelPolicy', 'dataChannelPolicy' | Format-List | Out-String)
Add-CheckResult -Section "6. FTP Request" -CheckName "6.2 Ensure FTP Logon attempt restrictions is enabled (Manual)" -Status (Test-Compliance -CheckId "6.2" -Output (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.ftpServer/security/authentication/denyByFailure' -name 'enabled')) -Details (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.ftpServer/security/authentication/denyByFailure' -name 'enabled' | Format-List | Out-String)

# 7. Transport Encryption
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.1 Ensure HSTS Header is set (Manual)" -Status "Not Available" -Details "Configuration details not available in CIS Microsoft IIS 10 benchmark v1.2.0 -11-15-2022"
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.2 Ensure SSLv2 is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.2" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    DisabledByDefault = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled', 'DisabledByDefault' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.3 Ensure SSLv3 is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.3" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    DisabledByDefault = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled', 'DisabledByDefault' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.4 Ensure TLS 1.0 is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.4" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    DisabledByDefault = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled', 'DisabledByDefault' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.5 Ensure TLS 1.1 is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.5" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    DisabledByDefault = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled', 'DisabledByDefault' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.6 Ensure TLS 1.2 is Enabled (Automated)" -Status (Test-Compliance -CheckId "7.6" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    DisabledByDefault = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled', 'DisabledByDefault' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.7 Ensure NULL Cipher Suites is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.7" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.8 Ensure DES Cipher Suites is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.8" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.9 Ensure RC4 Cipher Suites is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.9" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.10 Ensure AES 128/128 Cipher Suite is Disabled (Automated)" -Status (Test-Compliance -CheckId "7.10" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.11 Ensure AES 256/256 Cipher Suite is Enabled (Automated)" -Status (Test-Compliance -CheckId "7.11" -Output ([PSCustomObject]@{
    Enabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
})) -Details (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -ErrorAction SilentlyContinue | Format-List | Out-String)
Add-CheckResult -Section "7. Transport Encryption" -CheckName "7.12 Ensure TLS Cipher Suite ordering is Configured (Automated)" -Status (Test-Compliance -CheckId "7.12" -Output ([PSCustomObject]@{
    Functions = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue).Functions
})) -Details (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue | Format-List | Out-String)

# Create output directory in the same directory as the script
$outputDir = Join-Path -Path $PSScriptRoot -ChildPath "Reports"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -ErrorAction Stop | Out-Null
}

# Save the HTML report
$outputPath = Join-Path -Path $outputDir -ChildPath "IIS_CIS_Benchmark_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$htmlReport | Out-File -FilePath $outputPath -Encoding utf8
Write-Output "Report generated at: $outputPath"