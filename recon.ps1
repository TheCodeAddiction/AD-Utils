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
                Get-AllGroupMembersRecursivelyForPrint -groupName $memberName -level ($level + 1)
            }
        }
    }
}


# Prints all groups and users of each group recursivly, in a user friendly way.
function Get-AllGroupMembersRecursivelyForPrint ($groupName, $level) {
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
                Get-AllGroupMembersRecursivelyForPrint -groupName $memberName -level ($level + 1)
            }
            else {
                Write-Host "$indentation    - $memberName" -ForegroundColor Yellow  # Print member with indentation
            }
        }
    }
}



# Returns a list of objects that are memebers of a group or sub memebers of a group
function Get-AllSubGroupAndMembersRecursively($GroupNames) {
    $groupsAndUsers = @()
    foreach ($groupName in $GroupNames) {
        $groupObject = Find-Group -groupName $groupName

        if ($groupObject.Count -eq 0) {
            Write-Warning "Group '$groupName' not found."
            continue
        }

        foreach ($member in $groupObject[0].Properties["member"]) {
            $memberName = $member -replace '^CN=([^,]+),.*', '$1'

            if (Test-IfObjectIsAGroup -objectName $memberName) {
                $groupsAndUsers += $memberName
                $nestedMembers = Get-AllSubGroupAndMembersRecursively -GroupNames @($memberName)
                $groupsAndUsers += $nestedMembers
            } else {
                $groupsAndUsers += $memberName
            }
        }
    }
    return $groupsAndUsers
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
                        Get-AllGroupMembersRecursivelyForPrint -groupName $memberName -level 0
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


# Lists all important ACEs that a $objectName has over all users and groups
function Get-ImportantPermissionsOverObjects($objectName, $targetObjects){
    if ([string]::IsNullOrWhiteSpace($objectName)) {
        Write-Host "Error: Object name cannot be empty." -ForegroundColor Red
        return
    }
    $filter = "cn=$objectName"
    $subjectObject = Find-ObjectBasedOnFilter -baseLdapQuery $baseLdapQuery -filter $filter

    if ($subjectObject.Count -eq 0) {
        Write-Host "Object not found: $objectName" -ForegroundColor Red
        return
    }
    Write-Host "found our object: $subjectObject"


    $distinguishedNames = @()
    foreach ($obj in $targetObjects) {
        Write-Host $obj
        # check the ACE assigned to the object
        }
    }


# Takes a list of ObjectNames and checks if TargetUser have any dangerous permissions over those objects
function Find-ImportantPermissions($ObjectNames, $TargetUser) {
    $dangerousPermissions = @(
        'ForceChangePassword', 
        'AddMembers', 
        'GenericAll', 
        'GenericWrite', 
        'WriteOwner', 
        'WriteDacl', 
        'AllExtendedRights', 
        'Self'
    )

    $matchingRules = @()  # Initialize an array to store matching rules

    foreach ($name in $ObjectNames) {

        try {
            # Use DirectorySearcher to find the object by name
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=*)(name=$name))"
            $searcher.SearchScope = "Subtree"
            $result = $searcher.FindOne()

            if ($null -eq $result) {
                Write-Host "Object not found: $name" -ForegroundColor Red
                continue
            }
    
            # Get the Distinguished Name (DN) of the object
            $objectDN = $result.Properties["distinguishedname"][0]

            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$objectDN")
            $securityDescriptor = $directoryEntry.psbase.ObjectSecurity
            $accessRules = $securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

            foreach ($rule in $accessRules) {
                if ($rule.IdentityReference.Value -match $TargetUser) {  # Check if the rule applies to the target user
                    foreach ($permission in $dangerousPermissions) {  # Check for each dangerous permission
                        $adRight = [System.DirectoryServices.ActiveDirectoryRights]::$permission
                        if ($rule.ActiveDirectoryRights -band $adRight) {
                            $matchingRule = [PSCustomObject]@{
                                ObjectName      = $name
                                Identity        = $rule.IdentityReference.Value
                                ActiveDirectoryRights = $rule.ActiveDirectoryRights
                                ObjectType      = $rule.ObjectType
                                AccessControlType = $rule.AccessControlType
                                IsInherited     = $rule.IsInherited
                            }
                            $matchingRules += $matchingRule  # Add the custom object to the array
                            break  # Exit the inner loop once a match is found
                        }
                    }
                }
            }
            
        } catch {
            Write-Host "Error processing $name $_" -ForegroundColor Red
            continue
        }
    }
    return $matchingRules
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

function Find-AllGroupsObjectIsAMemberOf($objects){ 
    $groups = @()
    Foreach($obj in $objects) {
        Foreach ($prop in $obj.Properties.PropertyNames) {
            $propName = $prop
            $propValue = $obj.Properties[$prop]
            if ($propValue -is [System.Collections.IEnumerable] -and -not ($propValue -is [string])) {
                $propValue = $propValue -join ", "
            }
            if ($propName -eq "memberof") { 
                foreach ($group in $obj.Properties["memberof"]) {
                    $groupName = $group -replace '^CN=([^,]+),.*', '$1'
                    $groups += $groupName
                }
            }

        }
    }
    return $groups
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
    "fip"{ #Short for "Find-ImportantPermissions" 
        # Retrieves a username, checks the user's groups, recursively finds subgroup + members, and lists objects with dangerous ACEs controlled by the user.
        $objects = Find-UserBasedOnName -baseLdapQuery $baseLdapQuery -name $Parameter1
        $groups = Find-AllGroupsObjectIsAMemberOf -objects $objects
        $allSubGroupsAndMemebers = Get-AllSubGroupAndMembersRecursively -GroupNames $groups
        $fullTargetList = $allSubGroupsAndMemebers + $groups
        $dangerousPermissions = Find-ImportantPermissions -ObjectNames $fullTargetList -TargetUser $Parameter1
        foreach ($rule in $dangerousPermissions) {
            Write-Host "$TargetUser ($($rule.Identity)) has the following dangerous permission over: $($rule.ObjectName)"
            Write-Host "-----------------------------------" -ForegroundColor Cyan
            Write-Host "Rights: $($rule.ActiveDirectoryRights)" -ForegroundColor Red
            Write-Host "ObjectType: $($rule.ObjectType)"
            Write-Host "Type: $($rule.AccessControlType)"
            Write-Host "Inherited: $($rule.IsInherited)"
            Write-Host "-----------------------------------" -ForegroundColor Cyan
        }
    }

    "search"{
        $groups = Find-AllGroups -baseLdapQuery $baseLdapQuery -name $Parameter1
        $result = Find-ObjectBasedOnFilter -objects $groups
        Get-PropertiesFromObjectsPrettyPrint $result
    }
   
    default {
       Show-Options
    }
}

