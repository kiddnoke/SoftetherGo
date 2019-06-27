SoftEtherGo
===========

SoftEther VPN Server Golang Management API.

Golang implementation of SoftEther VPN management protocol. Can be used for controlling remote server, automation or statistics.

Usage example
-------------
```Golang


api := NewAPI('vpn.whitehouse.gov', 443, '123456password')

api.HandShake()

api.Test()

api.Disconnect()
```
