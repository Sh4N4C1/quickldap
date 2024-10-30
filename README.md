# quickldap

This is a python script I wrote to learn ldap, which contains some custom ldap syntax.

<p align="center">
<img src="https://raw.githubusercontent.com/Sh4N4C1/gitbook/main/images/quickldap.png" alt="sh4loader_v2">
</p>

# usage

```

  -h, --help            show this help message and exit
  -qall                 Query domain
                        users/groups/computers/admins/controller/blocked_users
  -qu                   Query domain users
  -qg                   Query domain groups
  -qc                   Query domain computers
  -qa                   Query domain admins
  -qdc                  Query domain controller
  -qbu                  Query domain blocked user
  -qd                   Query domain Delegation
  -qpp                  Query domain password policy
  -qfpp                 Query domain fine grained password policy
  -qasrep               Query domain DONT_REQ_PREAUTH users
  -qspn                 Query domain SPN users
  -qsspn                Query domain SPN users (Removes the 'servicePrincipalName'
                        filter)
  -qgm GROUP_NAME       Query a group members
  -qs SID               Query a sid detail
  -o O                  Save Path
  -request-user USER_NAME
                        Requests TGS for the SPN associated to the user specified
                        (just username)
  -detail OBECJT_NAME   Query a Object detail
  -acl OBECJT_NAME      Query a acl detail
  -target-domain TARGET_DOMAIN
                        Domain to query/request if different than the domain of the
                        user. Allows for retrieving delegation info across trusts.
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
```
