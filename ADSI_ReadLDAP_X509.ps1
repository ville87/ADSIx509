<#
.SYNOPSIS
    Script to read LDAP property using x509 client certificate authentication.

.DESCRIPTION
    
    This script uses x509 certificate based authentication against LDAP to read LDAP properties.
    Note: Some properties are not returned in human readable format. This is still work in progress...

    The certificate based authentication and LDAP_SERVER_WHO_AM_I request were taken from: 
    https://raw.githubusercontent.com/leechristensen/Random/master/PowerShellScripts/Get-LdapCurrentUser.ps1

    File-Name:  ADSI_ReadLDAP_X509.ps1
    Author:     Ville Koch (@vegvisir87, https://github.com/ville87)
    Version:    v1.0 (26/10/2024)

    TODO:
    - Figure out how to properly return all values in human readable format
    - Add more error handling
    - Add verbose logging possibility

.LINK
    https://github.com/ville87/ADSIx509

.EXAMPLE
    List properties of enabled computers in specific OU:
    .\ADSI_ReadLDAP_X509.ps1 -CertPath "C:\Users\jdoe\Desktop\rplant.pfx" -domain lab.local -DCIP 10.0.0.4 -LDAPFilter "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))((ms-mcs-admpwdexpirationtime=*)))" -DistinguishedName "OU=Workstations,DC=lab,DC=local"

#>

#################################### PARAMETERS ###########################################
[CmdletBinding()]
Param (
    # CertPath: Path to pfx client certificate used for authenticate to LDAP server
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateScript({
        if( -Not ($_ | Test-Path) ){
            throw "Provided certificate file does not exist"
        }
        return $true
    })]
    [System.IO.FileInfo]$CertPath,

    # domain: Domain to connect to. Should be in format domain.tld (currently no built-in validation)
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$domain,

    # DCIP: DC IP address to use to connect to via 636
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateScript({
        if( -Not ([bool]($_ -as [ipaddress]))){
            throw "Provided DC IP is not a valid IP address"
        }
        return $true
    })]
    [string]$DCIP,

    # LDAPFilter: The LDAP filter to run
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$LDAPFilter,

    # DistinguishedName: Location to search, if empty the builtin Users container of the domain will be set
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [string]$DistinguishedName = "CN=Users,DC=$(($domain -split "\.")[0]),DC=$(($domain -split "\.")[1])"
)

Begin {
    
#################################### VARIABLES ###########################################

    [string]$scriptPath             = Split-Path -Parent $MyInvocation.MyCommand.Definition;
    if($scriptPath -eq ''){ $scriptPath = (Get-Location).Path }
    [string]$DateTimeString         = Get-Date -Format 'dd_MM_yyyy-HH_mm_ss'
    [bool]$loggingenabled           = $false # if set to true, write output to logfile
    [string]$logfile                = "$DateTimeString"+"-ADSI_AddUser_X509.log"
    [string]$logfilepath            = "$scriptPath\$logfile"
    [string]$LogVariables           = $false # if set to true, variable values will be logged to logfile
    [array]$LIntUTCAttributes       = @("lastLogon","lastLogonTimestamp","pwdLastSet") # All attributes which are in format Large Int number of 100 nanosecond intervals since January 1, 1601 (UTC)
    [array]$UnixTimeStampAttributes = @("whenCreated","whenChanged") # All attributes which are in format unix epoch timestamp

#################################### FUNCTIONS ###########################################
    function printInfo { 
        Param (
        [Parameter(Mandatory = $true)][string]$info, # String to log
        [Parameter(Mandatory = $true)][ValidateSet("INFO","WARNING","ERROR")][string]$level
        )
        if($level -eq "ERROR"){
            Write-Host -ForegroundColor Red -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }elseif($level -eq "WARNING"){
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }else{
            Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }
            
        if($loggingenabled){
            "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info" | Out-File -FilePath $logfilepath -Append
        }
    }

    function convertLIntUTC {
        #  Value is stored as a large integer that represents the number of 100 nanosecond intervals since January 1, 1601 (UTC). A value of zero means that the last logon time is unknown.
        param (
            [Parameter(Mandatory = $true)]$value
        )
        $valuetohumanreadable = $( get-date ([datetime]::FromFileTime($value)) -f "dd/MM/yyyy HH:mm" )
        Return $valuetohumanreadable
    }

    function convertUnixEpoch {
        #  Value is stored as unix epoch
        param (
            [Parameter(Mandatory = $true)]$value
        )
        $valuetohumanreadable = get-date ((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(("$value")))) -Format "dd/MM/yyyy HH:mm"
        Return $valuetohumanreadable
    }

} # Begin

#################################### MAIN ################################################
Process {

    try {
        printInfo -info "Started script..." -level "INFO"
        if(([System.Net.Sockets.TcpClient]::new().ConnectAsync("$DCIP", 636).Wait(1000)) -eq $false){ 
            printInfo -info "Could not connect to $DCIP on port 636. Cannot continue..." -level "ERROR"
            Exit
        }
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Net")
        printInfo -info "Connecting to DC $DCIP on port 636 and starting authentication..." -level "INFO"
        $Ident = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList @("$DCIP`:636")
        $c = New-Object System.DirectoryServices.Protocols.LdapConnection $Ident
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, "", 'Exportable')
        $null = $c.ClientCertificates.Add($Cert)
        $c.SessionOptions.SecureSocketLayer = $true;
        $c.AuthType = "Kerberos"
        $c.SessionOptions.VerifyServerCertificate = {
            param($conn, [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)           
            Write-Verbose ($cert.ToString($true))
            $true
        }
        # 1.3.6.1.4.1.4203.1.11.3 = OID for LDAP_SERVER_WHO_AM_I_OID (see MS-ADTS 3.1.1.3.4.2 LDAP Extended Operations)
        $ExtRequest = New-Object System.DirectoryServices.Protocols.ExtendedRequest "1.3.6.1.4.1.4203.1.11.3"
        $resp = $c.SendRequest($ExtRequest)
        $str = [System.Text.Encoding]::ASCII.GetString($resp.ResponseValue)
        if([string]::IsNullOrEmpty($str)) {
            printInfo -info "Authentication against $DCIP using provided certificate failed! Cannot continue..." -level "ERROR"
            Exit
        } else {
            printInfo -info "Authenticated against $DCIP as user $str" -level "INFO"
        }

        $Request = New-Object System.DirectoryServices.Protocols.SearchRequest
        $Request.DistinguishedName = "$DistinguishedName"
        $Request.Filter = "$LDAPFilter"
        $Request.Scope = "Subtree"
        $Response = $c.SendRequest($Request)

        #$Properties = $Response.Entries[0].Attributes
        $Entries = $Response.Entries
        if($null -eq $Entries){
            $Entries = $false
            printInfo -info "No entries could be found in AD. Cannot continue..." -level "ERROR"
            #Exit
        }elseif($Entries.count -gt 1){
            printInfo -info "More than one entry was found in AD." -level "INFO"
        }
        foreach($Entry in $Entries){
            try{
                $attributes = $Entry.Attributes
                $output = ""
                foreach ($attributeName in $attributes.AttributeNames) {
                    $attributeValues = $attributes["$($attributeName)"]
                    $valueStrings = @()
                    # TODO: This does not work yet, because returned values are all byte values and some are returned in an unreadable format...
                    foreach ($value in $attributeValues) {
                        if ($value -is [byte[]]) {
                            $decodedValue = [System.Text.Encoding]::UTF8.GetString($value)
                        }elseif($attributeName -in $LIntUTCAttributes){
                            $decodedValue = convertLIntUTC -value $value
                        }elseif($attributeName -in $UnixTimeStampAttributes){
                            $decodedValue = convertUnixEpoch -value $value
                        } else {
                            # Either string or unhandled value type
                            $decodedValue = [string]$value
                        }
                        $valueStrings += $decodedValue
                    }
                    $output += "$attributeName`: $($valueStrings -join ', ')" + "`n"
                }
                printInfo -info "Found the following attributes:" -level "INFO"
                $output
            }catch{
                printInfo -info "Something went wrong when trying to list the properties" -level "ERROR"
            }
        }
        
        $c.Dispose()
        Write-host "############################################################################"
        printInfo -info "Script done." -level "INFO"
        $ErrorLevel = 0        
    } catch {
        printInfo -info "There was an error when running the script. Error:`r`n$_" -level "ERROR"
    }
} # Process

End {
    if($LogVariables -eq $true){
        # Log all variable values
        "######################### LOADED VARIABLES: ################################" | Out-File -FilePath $logfilepath -Append
        Get-ChildItem variable: | Out-File -FilePath $logfilepath -Append
        "############################################################################" | Out-File -FilePath $logfilepath -Append
    }
    if ($ErrorLevel -eq "0") {
        printInfo -info "Script ended succesfully" -level "INFO"
    }else{
        printInfo -info "Script ended with ErrorLevel: $ErrorLevel" -level "WARNING"
    }
} # End