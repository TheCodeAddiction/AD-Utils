param (
    [string]$FunctionKeyword,
    [string]$Parameter1        
)


# Define a list of standard AD groups from the provided Microsoft documentation
$standardGroups = @(
    "Account Operators", "Administrators", "Backup Operators", "Domain Admins", "Domain Guests",
    "Domain Users", "Enterprise Admins", "Group Policy Creator Owners", "Guests", "Incoming Forest Trust Builders",
    "Network Configuration Operators", "Performance Log Users", "Performance Monitor Users", "Pre-Windows 2000 Compatible Access",
    "Print Operators", "Remote Desktop Users", "Replicator", "Schema Admins", "Server Operators", "Users"
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
            
            if ($propName -eq "memberof") {
                Write-Host "Is a memeber of:" -ForegroundColor Cyan
                Foreach ($group in $obj.Properties["memberof"]) {
                    $groupName = $group -replace '^CN=([^,]+),.*', '$1'
                    
                    if ($standardGroups -contains $groupName) {
                        Write-Host " - $groupName"
                    } else {
                        Write-Host " - $groupName" -ForegroundColor Red
                    }
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




# Finds all SAM_NORMAL_USER_ACCOUNT objects. This might contain Computers and others. To find all "users" use Find-AllUsers
function Find-AllUsersAccounts($baseLdapQuery) {
    return Find-ObjectBasedOnFilter $baseLdapQuery "samAccountType=805306368"
}

# Finds all "users"
function Find-AllUsers($baseLdapQuery) { 
    $filter = "(&(objectCategory=person)(objectClass=user))"
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
    "fu" {  # Short for find user
        $result = Find-UserBasedOnName -baseLdapQuery $baseLdapQuery -name $Parameter1
        Get-PropertiesFromObjectsPrettyPrint $result  
    }
    "fa" {  # Short for Find-AllUsers
        $result = Find-AllUsers -baseLdapQuery $baseLdapQuery
        Get-PropertiesFromObjectsPrettyPrint $result  
    }
    "search"{
        $result = Find-ObjectBasedOnFilter -baseLdapQuery $baseLdapQuery -filter $Parameter1
        Get-PropertiesFromObjectsPrettyPrint $result
    }
    default {
       Show-Options
    }
    
}