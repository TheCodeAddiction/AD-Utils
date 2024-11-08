# About
AD recon / exploits tools that I have made to play around with LDAP and AD. 

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
    We would miss the fact that she is a memeber of dev.

- [ ] Add ACL tracking. I dont care what sub-groups exists under an account, if we can't do anything with those groups.