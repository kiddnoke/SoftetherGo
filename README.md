SoftEtherGo
===========

SoftEther VPN Server Golang Management API.

Golang implementation of SoftEther VPN management protocol. Can be used for controlling remote server, automation or statistics.

Usage example
-------------
```Golang


api := NewAPI('vpn.whitehouse.gov', 443, '123456password')

api.connect()
api.authenticate()
api.TestAPI_HandShake()

```
