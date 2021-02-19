Param(
    [Parameter(Mandatory=$false)][string]$UsersFilePath,
    [Parameter(Mandatory=$false)][string]$GroupsFilePath
)

if ($UsersFilePath) {
    #import csv backup
    $accounts = Import-Csv $UsersFilePath | Select-Object -Property *,OuPath

    #find and build ous.
    $ous = @()
    $accounts | ForEach-Object {
        $ou = ($PSItem.DistinguishedName).split(',')[1..99] -join ','
        $ous += $ou
        $PSitem.OuPath = $ou
    }

    $ous | Select-Object -Unique | Sort-Object { $_.value.length } | ForEach-Object {
        try {
            $ouname = $PSItem.split(',')[0] -replace 'OU=','' -replace 'CN=',''
            $oupath = $PSItem.split(',')[1..99] -join ','
            $PSItem
            New-ADOrganizationalUnit -Name $ouname -Path $oupath -ProtectedFromAccidentalDeletion $False
        } catch { 
            #$_
        }
    }

    #lets see if we can find an existing account and set it. If not create a new account with the incoming information.
    $accounts | ForEach-Object {
        
        try {
            $student = Get-Aduser $PSItem.ObjectGUID -ErrorAction SilentlyContinue
            Set-AdUser -Identity $student -SamAccountName $PSItem.SamAccountName -givenName $PSItem.GivenName -surname $PSItem.Surname -DisplayName $PSItem.DisplayName -UserPrincipalName $PSItem.UserPrincipalName -Name $PSItem.Name -EmployeeNumber $PSItem.EmployeeNumber -EmployeeID $PSItem.EmployeeID
        } catch {
            try {
                $student2 = Get-AdUser $PSItem.SamAccountName -ErrorAction SilentlyContinue
                Set-AdUser -Identity $student2 -SamAccountName $PSItem.SamAccountName -givenName $PSItem.GivenName -surname $PSItem.Surname -DisplayName $PSItem.DisplayName -UserPrincipalName $PSItem.UserPrincipalName -Name $PSItem.Name -EmployeeNumber $PSItem.EmployeeNumber -EmployeeID $PSItem.EmployeeID
            } catch {
                New-AdUser -SamAccountName $PSItem.SamAccountName -givenName $PSItem.GivenName -surname $PSItem.Surname -DisplayName $PSItem.DisplayName -UserPrincipalName $PSItem.UserPrincipalName -EmailAddress $PSItem.EmailAddress -Name $PSItem.Name -EmployeeNumber $PSItem.EmployeeNumber -EmployeeID $PSItem.EmployeeID -Path $PSItem.OuPath -Enabled $True -AccountPassword (ConvertTo-SecureString 'Pioneer12345' -AsPlainText -Force)
            }
        }

        $student = $null
        $student2 = $null

    }
}

if ($GroupsFilePath){
    $groups = Import-Csv $GroupsFilePath | Select-Object -Property *,OuPath

    #find and build ous.
    $ous = @()
    $groups | ForEach-Object {
        $ou = ($PSItem.DistinguishedName).split(',')[1..99] -join ','
        $ous += $ou
        $PSitem.OuPath = $ou
    }

    $ous | Select-Object -Unique | Sort-Object { $_.value.length } | ForEach-Object {
        try {
            $ouname = $PSItem.split(',')[0] -replace 'OU=','' -replace 'CN=',''
            $oupath = $PSItem.split(',')[1..99] -join ','
            $PSItem
            New-ADOrganizationalUnit -Name $ouname -Path $oupath -ProtectedFromAccidentalDeletion $False
        } catch { 
            #$_
        }
    }

  #lets see if we can find existing group and set its membership. If not create a new account with the incoming information.
  $groups | ForEach-Object {

    $groupName = $PSitem
    #exclude computers
    $members = (($groupName.members).split(';') | Where-Object { $groupName -notlike "*$" })

    try {
        $group = Get-ADGroup $groupName.ObjectGUID -ErrorAction SilentlyContinue
        if (($members | measure-object).count -ge 1) {
            Add-ADGroupMember -Identity $group -Members $members
        }
    } catch {
        try {
            $group2 = Get-ADGroup "$($groupName.Name)" -ErrorAction SilentlyContinue
            Add-ADGroupMember -Identity $group2 -Members $members
        } catch {
            New-AdGroup -Name "$($groupName.Name)" -GroupScope Universal
            Get-ADGroup "$($groupName.Name)" | Set-ADObject -Replace @{ mail = "$($groupName.EmailAddress)" }
            if (($members | measure-object).count -ge 1) {
                Add-ADGroupMember -Identity "$($groupName.Name)" -Members $members
            }
        }
    }

    $group = $null
    $group2 = $null

    }

}
