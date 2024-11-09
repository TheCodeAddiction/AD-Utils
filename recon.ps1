#Color scheme idea:
# Red = pay attantion here (like "Found a domain admin")
# Green = interesting information (like "none-standard group found")
# Cyan = focus here (like, here is where group and samaccount data is)
# Yellow = sub-focus. So if we use Cyan to highlight a headline (like "Memebers are") we can use Yellow to highlight the memeber's names.

param (
    [string]$FunctionKeyword,
    [string]$Parameter1        
)


# Define a list of standard AD groups that from the provided Microsoft documentation. 
$standardGroups = @(
    "Account Operators", "Administrators", "Backup Operators", "Domain Admins", "Domain Guests",
    "Domain Users", "Enterprise Admins", "Group Policy Creator Owners", "Guests", "Incoming Forest Trust Builders",
    "Network Configuration Operators", "Performance Log Users", "Performance Monitor Users", "Pre-Windows 2000 Compatible Access",
    "Print Operators", "Remote Desktop Users", "Replicator", "Schema Admins", "Server Operators", "Users"
)

# A list of high value ad groups
$highValueGroups = @(
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "Server Operators"
)


# Returns the current primary domain controller (PDC) which is the domain controller that we want to query to make sure all data is up-to-date.
function Get-PrimaryDomainController {
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $PDC = $domainObj.PdcRoleOwner.Name
    return $PDC
}

# Returns the distinguished name (DN) of the domain. 
function Get-DomainRootDistinguishedName {
    return ([adsi]'').distinguishedName
}

# Returns a list of all objects in the domain
function Find-AllObjectsFromRoot($baseLdapQuery) {
    $direntry = New-Object System.DirectoryServices.DirectoryEntry($baseLdapQuery)
    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
    return $dirsearcher.FindAll()
}

# Finds all objects in the domain based on a filter
function Find-ObjectBasedOnFilter($baseLdapQuery, $filter) {
    $direntry = New-Object System.DirectoryServices.DirectoryEntry($baseLdapQuery)
    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
    $dirsearcher.Filter = $filter
    return $dirsearcher.FindAll()
}

# Prints all properties in an object
function Get-PropertiesFromObjectsOld($objects) {
    Foreach($obj in $objects) {
        Foreach($prop in $obj.Properties) {
            $prop
        }
        Write-Host "-------------------------------"
    }
}

# Checks if an object is a group. Returns True if it is, False if it not.
function Test-IfObjectIsAGroup($objectName){
    $filter = "(&(objectCategory=group)(cn=$objectName))"
    $object = Find-ObjectBasedOnFilter -baseLdapQuery $baseLdapQuery -filter $filter
    if ($object.Count -gt 0) {
        return $true
    }
    else {
        return $false
    }
}

# Returns a list of members from an object
function Get-MembersFromObject($object) {
    $members = @()    
    if ($object -and $object.Properties["member"]) {
        foreach ($member in $object.Properties["member"]) {
            $members += $member
        }
    }
    
    return $members
}

# Prints all groups inside another group recursivly, in a user friendly way.
function Get-AllGroupsRecursively ($groupName, $level) {
    $groupObject = Find-Group -baseLdapQuery $baseLdapQuery -groupName $groupName
    
    if ($groupObject.Count -gt 0) {
        $indentation = " " * ($level * 4)
        
        if ($highValueGroups -contains $groupName) {
            Write-Host "$indentation- $groupName" -ForegroundColor Red
        }
        elseif ($standardGroups -contains $groupName) {
            Write-Host "$indentation- $groupName"
        }
        else {
            Write-Host "$indentation- $groupName" -ForegroundColor Green
        }

        foreach ($member in $groupObject[0].Properties["member"]) {
            $memberName = $member -replace '^CN=([^,]+),.*', '$1'
            if (Test-IfObjectIsAGroup $memberName) {
                Get-AllGroupMembersRecursively -groupName $memberName -level ($level + 1)
            }
        }
    }
}


# Prints all groups and users of each group recursivly, in a user friendly way.
function Get-AllGroupMembersRecursively ($groupName, $level) {
    $groupObject = Find-Group -baseLdapQuery $baseLdapQuery -groupName $groupName

    if ($groupObject.Count -gt 0) {
        $indentation = " " * ($level * 4)
        
        if ($highValueGroups -contains $groupName) {
            Write-Host "$indentation- $groupName" -ForegroundColor Red
        }
        elseif ($standardGroups -contains $groupName) {
            Write-Host "$indentation- $groupName"
        }
        else {
            Write-Host "$indentation- $groupName" -ForegroundColor Green
        }

        foreach ($member in $groupObject[0].Properties["member"]) {
            $memberName = $member -replace '^CN=([^,]+),.*', '$1'
            if (Test-IfObjectIsAGroup $memberName) {
                Get-AllGroupMembersRecursively -groupName $memberName -level ($level + 1)
            }
            else {
                Write-Host "$indentation    - $memberName" -ForegroundColor Yellow  # Print member with indentation
            }
        }
    }
}

# Prints all properties in an object but adds coloring for clarity
function Get-PropertiesFromObjectsPrettyPrint($objects) {
    Foreach($obj in $objects) {
        Foreach ($prop in $obj.Properties.PropertyNames) {
            $propName = $prop
            $propValue = $obj.Properties[$prop]
            
            if ($propValue -is [System.Collections.IEnumerable] -and -not ($propValue -is [string])) {
                $propValue = $propValue -join ", "
            }

            if ($propName -eq "samaccountname" ) {
                Write-Host "$propName $propValue" -ForegroundColor Cyan
                Continue
            }

            # What members are a part of a given object
            if ($propName -eq "member" ) {
                Write-Host "Members are:" -ForegroundColor Cyan
                Foreach ($member in $obj.Properties["member"]){
                    $memberName = $member -replace '^CN=([^,]+),.*', '$1'
                    if (Test-IfObjectIsAGroup $memberName){
                        Get-AllGroupMembersRecursively -groupName $memberName -level 0
                    }
                    else{
                        Write-Host " - $memberName" -ForegroundColor Yellow
                    }

                }
            }
            
            # What groups the object is a member of
            # TODO: un-nest groups to see all groups the memeber is a part of.
            if ($propName -eq "memberof") { 
                Write-Host "Is a member of:" -ForegroundColor Cyan
                foreach ($group in $obj.Properties["memberof"]) {
                    $groupName = $group -replace '^CN=([^,]+),.*', '$1'
                    Get-AllGroupsRecursively -groupName $groupName -level 0
                }
            }

            if ($propValue) {
                Write-Host "${propName}:" -ForegroundColor White -NoNewline
                Write-Host " $propValue" -ForegroundColor White
            } else {
                Write-Host "${propName}:" -ForegroundColor White -NoNewline
            }
            
        
        }
        Write-Host "-------------------------------"
    }
}


# Lists all ACL permissions that a objectName has over other objects
function Get-PermissionsForObject($objectName, $allDomainObjects){
    if ([string]::IsNullOrWhiteSpace($objectName)) {
        Write-Host "Error: Object name cannot be empty." -ForegroundColor Red
        return
    }
    $filter = "(&(objectCategory=user)(cn=$objectName))"
    $subjectObject = Find-ObjectBasedOnFilter -baseLdapQuery $baseLdapQuery -filter $filter

    if ($subjectObject.Count -eq 0) {
        Write-Host "Object not found: $objectName" -ForegroundColor Red
        return
    }

    # grabs a list of all objects in the domain that has a distinguishedName
    $distinguishedNames = @()
    foreach ($obj in $allDomainObjects) {
        if ($obj.Properties["distinguishedName"].Count -gt 0) {
            $distinguishedName = $obj.Properties["distinguishedName"][0]
            if (-not [string]::IsNullOrWhiteSpace($distinguishedName)) {
                $distinguishedNames += $distinguishedName
            }
        }
    }

    foreach ($distinguishedName in $distinguishedNames){
        Write-Host $distinguishedName
    }


}
# Grabs the ACL for a given object. This will list all objects that have permissions over the object submited with $objectName.
function Get-AclForObject($distinguishedName) {
    # Find the specified object in AD
    $filter = "(distinguishedname=$distinguishedName)"
    Write-Host "filter is $filter"
    $object = Find-ObjectBasedOnFilter -baseLdapQuery $baseLdapQuery -filter $filter

    if ($object.Count -eq 0) {
        Write-Host "Object not found: $distinguishedName" -ForegroundColor Red
        return
    }

    # Get the Distinguished Name (DN) of the found object
    $objectDN = $object[0].Properties.distinguishedname[0]
    Write-Host "Checking ACLs for object: $objectDN" -ForegroundColor Cyan

    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$objectDN")
    $securityDescriptor = $directoryEntry.psbase.ObjectSecurity
    $accessRules = $securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

    foreach ($rule in $accessRules) {
        $aclName = $rule.ActiveDirectoryRights.ToString()
        
        # Translate common GUIDs to friendly names
        $appliesToDescription = switch ($rule.ObjectType.ToString()) {
            "00000000-0000-0000-0000-000000000000" { "Entire object" }
            "bf967aba-0de6-11d0-a285-00aa003049e2" { "User objects" }
            "9b026da6-0d3c-465c-8bee-5199d7165cba" { "Group membership" }
            "19195a5a-6da0-11d0-afd3-00c04fd930c9" { "Computer objects" }
            "e48d0154-bcf8-11d1-8702-00c04fb96050" { "All properties" }
            default { "Unknown or other object type" }
        }

        # Identify important ACLs and their abuse potential
        switch ($aclName) {
            "ForceChangePassword" { $abuse = "abused with Set-DomainUserPassword" }
            "Add Member"          { $abuse = "abused with Add-DomainGroupMember" }
            "GenericAll"          { $abuse = "abused with Set-DomainUserPassword or Add-DomainGroupMember" }
            "GenericWrite"        { $abuse = "abused with Set-DomainObject" }
            "WriteOwner"          { $abuse = "abused with Set-DomainObjectOwner" }
            "WriteDACL"           { $abuse = "abused with Add-DomainObjectACL" }
            "AllExtendedRights"   { $abuse = "abused with Set-DomainUserPassword or Add-DomainGroupMember" }
            "Self"                { $abuse = "abused with Add-DomainGroupMember" }
            Default               { $abuse = $null }  # Skip unimportant ACLs
        }

        if ($abuse) {
            Write-Host "Important ACL Entry Found!" -ForegroundColor Green
            Write-Host " : $($rule.IdentityReference.Value)" -ForegroundColor Cyan
            Write-Host " Permission: $aclName" -ForegroundColor Yellow
            Write-Host " Abuse Potential: $abuse" -ForegroundColor Red
            Write-Host " Applies to: $appliesToDescription" -ForegroundColor Magenta
            Write-Host "-------------------------------" -ForegroundColor White
        }
    }
}


# Finds all SAM_NORMAL_USER_ACCOUNT objects. This might contain Computers and others. To find all "users" use Find-AllUsers
function Find-AllUsersAccounts($baseLdapQuery) {
    return Find-ObjectBasedOnFilter $baseLdapQuery "samAccountType=805306368"
}

# Finds all "users"
function Find-AllUsers($baseLdapQuery) { 
    $filter = "(&(objectCategory=person)(objectClass=user))"
    return Find-ObjectBasedOnFilter $baseLdapQuery $filter
}

# Finds all groups. This will find more groups than the usual "net.exe" command. Because we enumerate all AD objects including Domain Local groups. Not just global groups.
function Find-AllGroups ($baseLdapQuery){
    $filter = "(objectclass=group)"
    return Find-ObjectBasedOnFilter $baseLdapQuery $filter
}

function Find-Group ($baseLdapQuery, $groupName){
    $filter = "(&(objectCategory=group)(cn=$groupName))"
    return Find-ObjectBasedOnFilter $baseLdapQuery $filter
}

# Finds all users based on a name
function Find-UserBasedOnName($baseLdapQuery, $name) {
    return Find-ObjectBasedOnFilter $baseLdapQuery "(&(objectCategory=person)(name=$name))"
}


# Finds all users based on a name
function Find-ObjectBasedOnName($baseLdapQuery, $name) {
    return Find-ObjectBasedOnFilter $baseLdapQuery "(name=$name)"
}


function Show-Options {
    Write-Host -ForegroundColor Cyan "Available Options:"
    Write-Host ""
    Write-Host -ForegroundColor Cyan "Usage: .\recon.ps1 <function> <parameter>"
    Write-Host ""
    Write-Host -ForegroundColor Yellow "Options:"
    Write-Host -ForegroundColor Green "  fubon, find-userbasedonname <name>      " -NoNewline
    Write-Host "- Finds a user based on the provided name."
    Write-Host -ForegroundColor Green "  fa, find-allusers                       " -NoNewline
    Write-Host "- Lists all users in the domain."
    Write-Host ""
    Write-Host -ForegroundColor Yellow "Example:"
    Write-Host -ForegroundColor White "  .\recon.ps1 fubon 'jeffadmin'"
    Write-Host ""
}

$PDC = Get-PrimaryDomainController
$domainDN = Get-DomainRootDistinguishedName
$baseLdapQuery = "LDAP://$PDC/$domainDN"

if ($FunctionKeyword -eq "-h" -or $FunctionKeyword -eq "--help") {
    Show-Options
    return
}

# Switch to handle function calls based on keywords
switch ($FunctionKeyword.ToLower()) {
    "fu" {  # Short for Find-User
        $result = Find-UserBasedOnName -baseLdapQuery $baseLdapQuery -name $Parameter1
        Get-PropertiesFromObjectsPrettyPrint $result  
    }
    "fau" {  # Short for Find-AllUsers
        $result = Find-AllUsers -baseLdapQuery $baseLdapQuery
        Get-PropertiesFromObjectsPrettyPrint $result  
    }
    "fag"{ # Short for Find-AllGroups
        $result = Find-AllGroups -baseLdapQuery $baseLdapQuery
        Get-PropertiesFromObjectsPrettyPrint $result
    }

    "fg"{ # Short for Find-Group
        $result = Find-Group -baseLdapQuery $baseLdapQuery -groupName $Parameter1
        Get-PropertiesFromObjectsPrettyPrint $result
    }
    "getacl"{
        $allDomainObjects = Find-AllObjectsFromRoot -baseLdapQuery $baseLdapQuery
        Get-PermissionsForObject -objectName $Parameter1 -allDomainObjects $allDomainObjects
    }

    "search"{
        $result = Find-ObjectBasedOnFilter -baseLdapQuery $baseLdapQuery -filter $Parameter1
        Get-PropertiesFromObjectsPrettyPrint $result
    }
    default {
       Show-Options
    }
    
}