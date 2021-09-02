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

    $ous | Select-Object -Unique | Select-Object @{ Name = 'Name'; Expression = { $PSItem }},@{ Name = 'Length'; Expression = { $PSitem.length }} | Sort-Object -Property Length | Select-Object -ExpandProperty Name | ForEach-Object {
        try {
            #$PSItem
            $ouname = $PSItem.split(',')[0] -replace 'OU=','' -replace 'CN=',''
            $oupath = $PSItem.split(',')[1..99] -join ','
            
            if ($ous -notcontains $oupath) { 
                $ou2name = $PSItem.split(',')[1] -replace 'OU=','' -replace 'CN=',''
                $ou2path = $PSItem.split(',')[2..99] -join ','
                Write-Host "Missing parent OU $ou2name at $ou2path"
                try { New-ADOrganizationalUnit -Name $ou2name -Path $ou2path -ProtectedFromAccidentalDeletion $False -Verbose } catch {
                    #PSitem
                }
                $ous += $ou2path
            }

            Write-Host "Creating $ouname at $oupath"
            New-ADOrganizationalUnit -Name $ouname -Path $oupath -ProtectedFromAccidentalDeletion $False -Verbose
        } catch { 
            #$PSitem
        }
    }

    #lets see if we can find an existing account and set it. If not create a new account with the incoming information.
    $accounts | ForEach-Object {
        
        $account = $PSItem
        #$account
        Write-Host $account.SamAccountName,$account.OuPath
        #continue

        try {
            $student = Get-Aduser $account.ObjectGUID -ErrorAction SilentlyContinue
            Set-AdUser -Identity $student -SamAccountName $account.SamAccountName -givenName $account.GivenName -surname $account.Surname -DisplayName $account.DisplayName -UserPrincipalName $account.UserPrincipalName -Name $account.Name -EmployeeNumber $account.EmployeeNumber -EmployeeID $account.EmployeeID
            try { Move-ADObject -Identity $student -TargetPath "$($account.OuPath)" } catch {}
        } catch {
            try {
                if ($account.EmployeeNumber -ge 1) {
                    $student2 = Get-AdUser -Filter { EmployeeNumber -eq "$($account.EmployeeNumber)" }
                } else {
                    $student2 = Get-AdUser "$($account.SamAccountName)"
                }
                Set-AdUser -Identity $student2 -SamAccountName "$($account.SamAccountName)" -givenName "$($account.GivenName)" -surname "$($account.Surname)" -DisplayName "$($account.DisplayName)" -UserPrincipalName "$($account.UserPrincipalName)" -Name "$($account.Name)" -EmployeeNumber "$($account.EmployeeNumber)" -EmployeeID "$($account.EmployeeID)"
                try { Move-ADObject -Identity $student2 -TargetPath "$($account.OuPath)" } catch {}
            } catch {
                New-AdUser -SamAccountName "$($account.SamAccountName)" -givenName "$($account.GivenName)" -surname "$($account.Surname)" -DisplayName "$($account.DisplayName)" -UserPrincipalName "$($account.UserPrincipalName)" -EmailAddress "$($account.EmailAddress)" -Name "$($account.Name)" -EmployeeNumber "$($account.EmployeeNumber)" -EmployeeID "$($account.EmployeeID)" -Path "$($account.OuPath)" -Enabled $True -AccountPassword (ConvertTo-SecureString 'Pioneer12345' -AsPlainText -Force) -Verbose
                $student3 = Get-AdUser $account.SamAccountName -ErrorAction SilentlyContinue
                try { Move-ADObject -Identity $student3 -TargetPath "$($account.OuPath)" } catch {}
            }
        }

        $student = $null
        $student2 = $null
        $student3 = $null

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

    #$groupName
    $groupName = $PSitem
    $groupName
    Write-Host $groupName.SamAccountName,$GroupName.OuPath
    
    #exclude computers
    $members = @()
    $members += (($groupName.members).split(';') | Where-Object { $groupName -notlike "*$" })

    try {
        $group = Get-ADGroup $groupName.ObjectGUID -ErrorAction SilentlyContinue
        if (($members | measure-object).count -ge 1) {
            try {
                Add-ADGroupMember -Identity $group -Members $members
            } catch {}
        }
    } catch {
        try {
            $group2 = Get-ADGroup "$($groupName.Name)" -ErrorAction SilentlyContinue
            try {
                if (($members | measure-object).count -ge 1) {
                    try {
                        Add-ADGroupMember -Identity $group2 -Members $members
                    } catch {}
                }
                try { Move-ADObject -Identity $group2 -TargetPath "$($groupName.OuPath)" } catch {}
            } catch {
                #$_
            }
        } catch {
            New-AdGroup -Name "$($groupName.Name)" -GroupScope Global -Path "$($groupName.OuPath)"
            if (-Not($($groupName.EmailAddress) -eq '' -or $NULL -eq $($groupName.EmailAddress))) {
                Get-ADGroup "$($groupName.Name)" | Set-ADObject -Replace @{ mail = "$($groupName.EmailAddress)" }
            }
            if (($members | measure-object).count -ge 1) {
                try { Add-ADGroupMember -Identity "$($groupName.Name)" -Members $members } catch { $_ }
            }
        }
    }

    $group = $null
    $group2 = $null

    }

}
