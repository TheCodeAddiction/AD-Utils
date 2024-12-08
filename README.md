# About
This is a collection of AD scripts/tools, some made for fun and to play around with AD, some made to be useful on an engagement!

# recon.ps1
## About
recon.ps1 is a AD enumeration script focused on enumerating AD using LDAP and structuring the information in an 
easily readable format. 

## Usage
* `.\recon.ps1 fu <username>` - Enumerates the user and finds all groups the user is a member of and prints it in a nice and readable way
* `.\recon.ps1 fau` -  Enumerates all users and finds all groups the users are a member of and prints it in a nice and readable way
* `.\recon.ps1 fag` - Enumerates all groups and prints the information in a nice and readable way
* `.\recon.ps1 fg <group>` - Enumerates the group and prints the information in a nice and readable way
* `.\recon.ps1 fip <username>` - Lists all dangerous permission a user has over groups / sub-groups and users in those groups.
*  `.\recon.ps1 search <ldap query>` - Executes the ldap queries and attempts to print the information in a nice and readable way


# TODO
- [ ] When looking at an object, it will recursivly un-nest any nested groups. However, it only does it one way, meaning it can do: 

    ```
    .\recon.ps1 fg "Management *"
        ...
        Is a member of:
        - Development Department
            - Management Department
                - jen
        Members are:
        - jen
    ``` 
    Here we can clearly see that jen is not just a memeber of managment, but is also a member of dev. Meaning jen has both the permissiosn of managment, but also dev, very nice!

    However, if we search for jen as a user
    ```
    .\recon.ps1 fu "jen"
        ...
        name: jen
        Is a member of:
        - Management Department
        ...
    ```
    

- [ ] Currently `fip <username>` only works on users
- [ ] Currently `fip <username>` only checks the user's groups and nestet-sub groups. It does not check every object in AD. I want a function that checks if the user has
any dangerous permissions over any object in AD, even thought this would make a lot of noice and take ages in large AD enviorments, it would be a very useful feature
- [ ] Currently `fu` and `fau` does not automatily do a `fip` check. When I list information about a user with `fu` I want the output to highlight if this user 
has any dangerous permissions over an object in the print.