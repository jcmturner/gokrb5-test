<powershell>

# Variables
$DomainName = "user.gokrb5"
$SisterName = "res.gokrb5"
$NetbiosName = "USER"
$ip = "192.168.88.100"
$SisterIP = "192.168.88.101"

#Get the instance's ID from metadata
$webclient = new-object net.webclient
$instanceid = $webclient.Downloadstring('http://169.254.169.254/latest/meta-data/instance-id')
#Create the tag object to track stages of set up
Import-Module -Name AWSPowershell
$tag = New-Object Amazon.EC2.Model.Tag
$tag.key = "gokrb5-stage"
#Get the current value of the stage of set up
try {
    $describeTag = Get-EC2Tag -Filter @{Name="key";Value=$tag.key},@{Name="resource-id";Value="$instanceid"}
    $tag.Value = $describeTag.Value
}
catch {
    Write-Host "Could not get instance tag - waiting and reboot"
    Start-Sleep -seconds 15
    Restart-Computer -Force
}


switch($tag.Value) {
    "0" { ### Configure as Domain Controller for new forest/domain
        $tag.Value = "0-processing"
        $tag = New-EC2Tag -Resource $instanceid -Tag $tag -PassThru -Force
        #Rename-Computer -NewName "$NetbiosName-DC"
        # Not needed in AWS
        #New-NetIPAddress –InterfaceAlias $interfaceAlias –IPAddress $ip –PrefixLength $ipMask -DefaultGateway $gw

        Import-Module ServerManager
        Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
        Import-Module ADDSDeployment

        $password = ConvertTo-SecureString -String ZAQ!1qaz -AsPlainText -Force
        Install-ADDSForest -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012R2" -DomainName $DomainName -DomainNetbiosName $netbiosName -ForestMode "Win2012R2" -InstallDns -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -SafeModeAdministratorPassword $password -Force -NoRebootOnCompletion

        $tag.Value = "1"
        $tag = New-EC2Tag -Resource $instanceid -Tag $tag -PassThru -Force

        Restart-Computer -Force
    }
    "1" {
        $tag.Value = "1-processing"
        $tag = New-EC2Tag -Resource $instanceid -Tag $tag -PassThru -Force
        Import-Module ServerManager
        Import-Module ADDSDeployment

        # Configure DNS resolution
        Add-DnsServerForwarder -IPAddress 169.254.169.253 -PassThru
        Add-DnsServerConditionalForwarderZone -Name $SisterName -MasterServers $SisterIP -PassThru
        Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses 127.0.0.1

        # Create AD Users and Groups
        $domainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
        Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $false -Identity $domainPasswordPolicy
        $password = ConvertTo-SecureString -String passwordvalue -AsPlainText -Force
        $GivenName = "Test"
        $Surname = "User"
        $UsernamePrefix = "testuser"

        for ($i=1; $i -lt 4; $i++) {
            $user =	New-ADUser -Name "$UsernamePrefix$i" -GivenName $GivenName -Surname "$Surname $i" -DisplayName "$GivenName $Surname $i" -EmailAddress "$UsernamePrefix$i@$DomainName" -Enabled $true -AccountPassword $password -ChangePasswordAtLogon $false -PasswordNeverExpires $true -KerberosEncryptionType RC4,AES128,AES256 -UserPrincipalName $UsernamePrefix$i@$DomainName -ServicePrincipalNames "HTTP/user$i.$DomainName" -PassThru
            $group = New-ADGroup -Name "testGroup$i" -SamAccountName "testgroup$i" -GroupCategory Security -GroupScope Global -DisplayName "Test Group $i" -Description "Test Group $i" -PassThru
            Add-ADGroupMember -Identity $group -Members $user
        }

        Get-ADUser -filter 'samAccountName -eq "testuser3"' | Set-ADAccountControl  -doesnotrequirepreauth $true

        $password = ConvertTo-SecureString -String ZAQ!1qaz -AsPlainText -Force
        $user =	New-ADUser -Name "gokrb5-adadmin" -Enabled $true -AccountPassword $password -ChangePasswordAtLogon $false -PasswordNeverExpires $true -UserPrincipalName "gokrb5-adadmin@$DomainName" -PassThru
        Add-ADGroupMember -Identity "Domain Admins" -Members $user

        # Set supported enctypes to RC4-HMAX, AES128_HMAC_SHA1 and AES256_HMAC_SHA1
        Set-GPRegistryValue -Domain $DomainName -Name "Default Domain Policy" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ValueName "SupportedEncryptionTypes" -Value 28 -Type DWord

        # Enabled claims in KDC - Group Policy: KDC support for claims
        Set-GPRegistryValue -Domain $DomainName -Name "Default Domain Policy" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\KDC\Parameters" -ValueName "EnableCbacAndArmor" -Value 1 -Type DWord
        Set-GPRegistryValue -Domain $DomainName -Name "Default Domain Policy" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\KDC\Parameters" -ValueName "CbacAndArmorLevel" -Value 2 -Type DWord

        $tag.Value = "2"
        $tag = New-EC2Tag -Resource $instanceid -Tag $tag -PassThru -Force
        Restart-Computer -Force
    }
    "2" {
        $tag.Value = "finished"
        $tag = New-EC2Tag -Resource $instanceid -Tag $tag -PassThru -Force
    }
}
</powershell>
<persist>true</persist>
