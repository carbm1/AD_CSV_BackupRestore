if (-Not(Test-Path .\archives)) { New-Item -ItemType Directory -Path .\archives }

$timestamp = get-date -Format yyyy-MM-dd-HH-mm-ss

#Backup Users
Get-ADUser -Filter * -Properties DisplayName,givenName,Surname,EmployeeNumber,EmployeeID,SamAccountName,UserPrincipalName,EmailAddress,DistinguishedName,Enabled,Fax,HomePhone,Office,ObjectGUID,objectSid | ConvertTo-Csv -UseQuotes AsNeeded -NoTypeInformation | Out-File ".\archives\$($timestamp)_users_ad_structure.csv"

#Backup Groups and Memberships
$groupmemberships = @()

Get-ADGroup -Filter * -Properties mail | ForEach-Object {
    
    try {
        $members = (Get-ADGroupMember -Identity "$PSItem" | Select-Object -ExpandProperty SamAccountName) -join ';'
    } catch {
        #slower but accepts larger numbers
        $members = (Get-ADUser -LDAPFilter "(&(objectCategory=user)(memberof=$PSItem))" | Select-Object -ExpandProperty SamAccountName) -join ';'
    }
    
    $groupmemberships += [PSObject]@{ name = "$($PSItem.Name)"; DistinguishedName = "$PSItem"; ObjectGUID = "$($PSitem.ObjectGUID)"; EmailAddress = "$($PSItem.mail)"; members = "$members"}

}

#converting to json and back just to get it to export is dumb.
$groupmemberships | ConvertTo-Json | ConvertFrom-Json | ConvertTo-Csv -UseQuotes AsNeeded -NoTypeInformation | Out-File ".\archives\$($timestamp)_groups_ad_structure.csv"
