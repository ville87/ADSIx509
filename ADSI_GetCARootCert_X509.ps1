<#
.SYNOPSIS
    Script to export a target DCs CA root certificate from LDAP into a cer file

.DESCRIPTION
    
    This script gets the LDAP property "caCertificate" from a target domain controller and exports it as a x509 certificate

    File-Name:  ADSI_GetCARootCert_X509.ps1
    Author:     Ville Koch (@vegvisir87, https://github.com/ville87)
    Version:    v1.0 (30.09.2024)


.LINK
    https://github.com/ville87/ADSIx509

.EXAMPLE
    Get the Root CA certificate via LDAP and export it as a cer file:
    .\ADSI_GetCARootCert_X509.ps1 -domain lab.local -dc dc1.lab.local -CertExportPath C:\users\jdoe\Desktop
#>

#################################### PARAMETERS ###########################################
[CmdletBinding()]
Param (
    # domain: Domain to connect to. Should be in format domain.tld (currently no built-in validation)
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$domain, 

    # dc: Domain controller to connect to. Should be in format hostname.domain.tld (currently no built-in validation)
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$dc,

    # CertExportPath: Path to where the CA root cert should be stored
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [System.IO.FileInfo]$CertExportPath
)

Begin {
    
#################################### VARIABLES ###########################################

    [string]$baseDN                 = "DC=$(($domain -split "\.")[0]),DC=$(($domain -split "\.")[1])"

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
            
        # Load the required namespace and get the AD property
        Add-Type -AssemblyName System.DirectoryServices
        $ldapPath = "LDAP://$dc/CN=Public Key Services,CN=Services,CN=Configuration,$baseDN"
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = "(objectClass=pKIEnrollmentService)"
        $searcher.PropertiesToLoad.Add("cACertificate") | Out-Null
        $searchResults = $searcher.FindAll()

        # convert the resulting byte array to a cert
        foreach ($result in $searchResults) {
            $certificates = $result.Properties["cACertificate"]
            foreach ($cert in $certificates) {
                [byte[]] $DERCert = $cert
                $X509CertificateCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $X509CertificateCollection.Import($DERCert, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
                Write-Output "##############   Found cert:   ################`r`n $X509CertificateCollection"
                foreach ($certCollection in $X509CertificateCollection) {
                    $cerFilePath = Join-Path $CertExportPath "$($certCollection.Thumbprint).cer"
                    $cerBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($cerFilePath, $cerBytes)
                    Write-Output "CER file created here: $cerFilePath"
                }
            }
        }
    } catch {
        printInfo -info "There was an error when running the script. Error:`r`n$_" -level "ERROR"
    }
} # Process

End {

} # End