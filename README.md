# ADSIx509
Author:     Ville Koch (@vegvisir87, https://github.com/ville87)   
Version:    v1.2 (23/10/2024)   

> [!WARNING]  
> These scripts were made for testing purposes in an Active Directory domain.    
> It is not advised to use this in a production environment!   

## ADSI_AddUser_X509.ps1
The script `ADSI_AddUser_X509.ps1` uses x509 certificate based authentication against LDAP to create a user or take an existing user and if specified add it as a member to a specified group. 
- The user will be enabled after creation (userAccountControl=512). 
- The users distinguishedName will be built from the given domain name, like: `CN=Username,CN=Users,DC=lab,DC=local.`
- When looking for users or group, the Base DN is currently always the container *CN=Users,DC=lab,DC=local*.
   
The certificate based authentication and LDAP_SERVER_WHO_AM_I request were taken from:   
https://raw.githubusercontent.com/leechristensen/Random/master/PowerShellScripts/Get-LdapCurrentUser.ps1

TODO:   
- Figure out how System.DirectoryServices.Protocols.SearchRequest has to be set to look in any container / subcontainers / OUs, not just CN=users...
- Add more error handling
- Add verbose logging possibility

### Examples 
Create a new user and add it to the Domain Admins group:   
```powershell
.\ADSI_AddUser_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4 -CreateUser Y -samAccountName baduser1 -givenName Hans -sn Landa -AddToGroup Y -groupName "Domain Admins"
```

Take an existing user and add it to the Domain Admins group:   
```powershell
.\ADSI_AddUser_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4 -CreateUser N -samAccountName someuser1 -AddToGroup Y -groupName "Domain Admins"
```

Only create a new user:   
```powershell
.\ADSI_AddUser_X509.ps1 -CertPath C:\TEMP\domadmin.pfx -domain lab.local -DCIP 10.0.0.4 -CreateUser Y -samAccountName anotheruser1 -givenName Mister -sn Blonde -AddToGroup N
```

## ADSI_GetCARootCert_X509.ps1
This script gets the LDAP property "caCertificate" from a target domain controller and exports it as a x509 certificate

### Examples 
Get the Root CA certificate via LDAP and export it as a cer file:   
```powershell
.\ADSI_GetCARootCert_X509.ps1 -domain lab.local -dc dc1.lab.local -CertExportPath C:\users\jdoe\Desktop
```
