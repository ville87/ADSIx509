<#
.SYNOPSIS
    Script to create a new domain user and it to an AD group using x509 client certificate authentication.

.DESCRIPTION
    This script was made for testing purposes in an Active Directory domain. 
    It is not advised to use this in a production environment!

    This script uses x509 certificate based authentication against LDAP to create a user or take an existing user and if specified
    add it as a member to a specified group.
    The user will be enabled after creation (userAccountControl=512).
    The users distinguishedName will be built from the given domain name, like: CN=Username,CN=Users,DC=lab,DC=local.
    When looking for users or group, the Base DN is currently always the container CN=Users,DC=lab,DC=local.

    The certificate based authentication and LDAP_SERVER_WHO_AM_I request were taken from: 
    https://raw.githubusercontent.com/leechristensen/Random/master/PowerShellScripts/Get-LdapCurrentUser.ps1

    File-Name:  ADSI_AddUser_X509.ps1
    Author:     Ville Koch (@vegvisir87, https://github.com/ville87)
    Version:    v1.2 (23/10/2024)

    TODO:
    - Figure out how System.DirectoryServices.Protocols.SearchRequest has to be set to look in any container / subcontainers / OUs, not just CN=users...
    - Add more error handling
    - Add verbose logging possibility

.LINK
    https://github.com/ville87/ADSIx509

.EXAMPLE
    Create a new user and add it to the Domain Admins group:
    .\ADSI_AddUser_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4 -CreateUser Y -samAccountName baduser1 -givenName Hans -sn Landa -AddToGroup Y -groupName "Domain Admins"

    Take an existing user and add it to the Domain Admins group:
    .\ADSI_AddUser_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4 -CreateUser N -samAccountName someuser1 -AddToGroup Y -groupName "Domain Admins"

    Only create a new user:
    .\ADSI_AddUser_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4 -CreateUser Y -samAccountName anotheruser1 -givenName Mister -sn Blonde -AddToGroup N
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

    # CreateUser: If set to Y, the new user will be created
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateSet("Y", "N")]
    [string]$CreateUser,

    # samAccountName: samAccountName of user that will be created in AD
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$samAccountName,
    
    # givenName: givenName (firstname) of user that will be created in AD
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [string]$givenName, 

    # sn: surname of user that will be created in AD
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [string]$sn,

    # AddToGroup: If set to Y, the new user will be added to a given group in AD
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateSet("Y", "N")]
    [string]$AddToGroup,

    # groupName: group to which the user will be added
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [string]$groupName,

    # groupDN: If the AD group is not in the default "Users" container, specify the path of the DN here
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [string]$groupDN

)

Begin {
    
#################################### VARIABLES ###########################################

    [string]$scriptPath             = Split-Path -Parent $MyInvocation.MyCommand.Definition;
    if($scriptPath -eq ''){ $scriptPath = (Get-Location).Path }
    [string]$DateTimeString         = Get-Date -Format 'dd_MM_yyyy-HH_mm_ss'
    [bool]$loggingenabled           = $false # if set to true, write output to logfile
    [string]$logfile                = "$DateTimeString"+"-ADSI_AddUser_X509.log"
    [string]$logfilepath            = "$scriptPath\$logfile"
    [string]$baseDN                 = "DC=$(($domain -split "\.")[0]),DC=$(($domain -split "\.")[1])"
    [string]$UserDN                 = "CN=$samAccountName,CN=Users,$baseDN"
    [string]$LogVariables           = $false # if set to true, variable values will be logged to logfile

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

} # Begin

#################################### MAIN ################################################
Process {

    try {
        printInfo -info "Started script..." -level "INFO"
        if(($AddToGroup -eq "Y") -and ($null -eq $groupName)){
            printInfo -info "Value for parameter groupName is missing! Cannot continue..." -level "ERROR"
            Exit
        }
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
        if($CreateUser -eq "Y"){
            if((!$givenName) -or (!$sn)){
                printInfo -info "It was chosen to create a new user, however one of the params givenName or sn was not specified! Cannot continue..." -level "ERROR"
                Exit
            }
            # Specify user attributes
            $userAttributes = @{
                "samAccountName" = "$samAccountName"
                "givenName"      = "$givenName"
                "sn"             = "$sn"
                "userPrincipalName" = "$samAccountName@$Domain"
                "objectClass"        = @("top", "person", "organizationalPerson", "user")
                "userAccountControl" = "514"  # account has to be disabled, otherwise it fails
            }
            printInfo -info "Creating user $samAccountName..." -level "INFO"
            $addRequest = New-Object System.DirectoryServices.Protocols.AddRequest
            $addRequest.DistinguishedName = $UserDN
            foreach ($attribute in $userAttributes.GetEnumerator()) {
                $addRequest.Attributes.Add(
                    (New-Object System.DirectoryServices.Protocols.DirectoryAttribute $attribute.Key, $attribute.Value)
                )
            }
            ###################### Add the user #######################
            $addResponse = $c.SendRequest($addRequest)
            if($addResponse.ResultCode -notlike "Success"){ 
                printInfo -info "Something went wrong when creating the account! `r`nErrormessage: $($addResponse.ErrorMessage). Cannot continue..." -level "ERROR"
                Exit 
            }else{
                printInfo -info "User was created." -level "INFO"
            }
            ###################### Set password #######################
            # TODO: Add error handling
            $newPassword = Read-Host "Please define a password for the new account. Make sure it is according to the pw policy!" -AsSecureString
            $modifyOperation = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $modifyOperation.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            $modifyOperation.Name = "unicodePwd"
            $modifyOperation.Add([Text.Encoding]::Unicode.GetBytes(('"{0}"' -f [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword)))))
            $modifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest $userDN, $modifyOperation
            $modifyResponse = $c.SendRequest($modifyRequest)
            printInfo -info "Password was set for the user." -level "INFO"

            ###################### Enable account ####################### 
            # TODO: Add error handling
            $modifyOperation = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $modifyOperation.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            $modifyOperation.Name = "userAccountControl"
            $modifyOperation.Add("512")
            $modifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest $userDN, $modifyOperation
            $modifyResponse = $c.SendRequest($modifyRequest)
            printInfo -info "Enabled the account." -level "INFO"
        }else{
            printInfo -info "It was chosen to not create a user, checking if it can be found in AD..." -level "INFO"
            $Request = New-Object System.DirectoryServices.Protocols.SearchRequest
            $Request.DistinguishedName = "CN=users,$baseDN"
            $Request.Filter = "(&(samAccountType=805306368)(samaccountname=$samaccountname))"
            $Request.Scope = "Subtree"
            $Response = $c.SendRequest($Request)
            $UserResult = $Response.Entries[0].DistinguishedName
            if($null -eq $UserResult){
                $UserOK = $false
                printInfo -info "The user could not be found in AD. Cannot continue..." -level "ERROR"
                Exit
            }elseif($UserResult.count -gt 1){
                printInfo -info "More than one user was found in AD:`r`n$UserResult`r`nCannot continue..." -level "ERROR"
                Exit
            }
        }


        if($AddToGroup -eq "Y"){
            ###################### Add to group #######################
            # TODO: Add better error handling
            printInfo -info "Looking up provided group..." -level "INFO"
            if(!($groupDN)){
                # groupDN parameter was not specified, assuming the group is in the default users container...
                printInfo -info "Searching DistinguishedName of group..." -level "INFO"
                $Request = New-Object System.DirectoryServices.Protocols.SearchRequest
                $Request.DistinguishedName = "CN=Users,$baseDN"
                $Request.Filter = "(&(cn=$groupName)(objectClass=Group))"
                $Request.Scope = "Subtree"
                $Response = $c.SendRequest($Request)
                $GroupResult = $Response.Entries[0].DistinguishedName
                if($null -eq $GroupResult){
                    $GroupOK = $false
                    printInfo -info "The group's DistinguishedName could not be identified..." -level "WARNING"
                }else{
                    $GroupOK = $true
                    $groupDN = $GroupResult
                }
            }else{
                printInfo -info "Looking for provided DistinguishedName $groupDN in domain..." -level "INFO"
                $Request = New-Object System.DirectoryServices.Protocols.SearchRequest
                $Request.DistinguishedName = $groupDN
                $Request.Filter = "(distinguishedName=$groupDN)"
                $Request.Scope = "Base"
                $Response = $c.SendRequest($Request)
                $GroupResult = $Response.Entries[0].DistinguishedName
                if($null -eq $GroupResult){
                    $GroupOK = $false
                    printInfo -info "The group's DistinguishedName could not be identified..." -level "WARNING"
                }else{
                    $GroupOK = $true
                }
            }
            if($GroupOK -ne $true){
                printInfo -info "Group $groupName could not be found! Cannot add user to group..." -level "WARNING"
            }else{
                printInfo -info "Group $groupName was found, adding user..." -level "INFO"
                $ModifyOperation = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $ModifyOperation.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
                $ModifyOperation.Name = "member"
                $ModifyOperation.Add($UserDN)
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest -ArgumentList $groupDN,$ModifyOperation
                $ModifyResponse = $c.SendRequest($ModifyRequest)
                if($ModifyResponse.ResultCode -notlike "Success"){ 
                    printInfo -info "Something went wrong when trying to add the account to the group! `r`nErrormessage: $($ModifyResponse.ErrorMessage)." -level "ERROR"
                    Exit 
                }else{
                    printInfo -info "User added to group." -level "INFO"
                }
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