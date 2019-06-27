package softetherApi

/*
	Error Code
*/
const (
	ERR_NO_ERROR = iota
	ERR_CONNECT_FAILED
	ERR_SERVER_IS_NOT_VPN
	ERR_DISCONNECTED
	ERR_PROTOCOL_ERROR
	ERR_CLIENT_IS_NOT_VPN
	ERR_USER_CANCEL
	ERR_AUTHTYPE_NOT_SUPPORTED
	ERR_HUB_NOT_FOUND
	ERR_AUTH_FAILED
	ERR_HUB_STOPPING
	ERR_SESSION_REMOVED
	ERR_ACCESS_DENIED
	ERR_SESSION_TIMEOUT
	ERR_INVALID_PROTOCOL
	ERR_TOO_MANY_CONNECTION
	ERR_HUB_IS_BUSY
	ERR_PROXY_CONNECT_FAILED
	ERR_PROXY_ERROR
	ERR_PROXY_AUTH_FAILED
	ERR_TOO_MANY_USER_SESSION
	ERR_LICENSE_ERROR
	ERR_DEVICE_DRIVER_ERROR
	ERR_INTERNAL_ERROR
	ERR_SECURE_DEVICE_OPEN_FAILED
	ERR_SECURE_PIN_LOGIN_FAILED
	ERR_SECURE_NO_CERT
	ERR_SECURE_NO_PRIVATE_KEY
	ERR_SECURE_CANT_WRITE
	ERR_OBJECT_NOT_FOUND
	ERR_VLAN_ALREADY_EXISTS
	ERR_VLAN_INSTALL_ERROR
	ERR_VLAN_INVALID_NAME
	ERR_NOT_SUPPORTED
	ERR_ACCOUNT_ALREADY_EXISTS
	ERR_ACCOUNT_ACTIVE
	ERR_ACCOUNT_NOT_FOUND
	ERR_ACCOUNT_INACTIVE
	ERR_INVALID_PARAMETER
	ERR_SECURE_DEVICE_ERROR
	ERR_NO_SECURE_DEVICE_SPECIFIED
	ERR_VLAN_IS_USED
	ERR_VLAN_FOR_ACCOUNT_NOT_FOUND
	ERR_VLAN_FOR_ACCOUNT_USED
	ERR_VLAN_FOR_ACCOUNT_DISABLED
	ERR_INVALID_VALUE
	ERR_NOT_FARM_CONTROLLER
	ERR_TRYING_TO_CONNECT
	ERR_CONNECT_TO_FARM_CONTROLLER
	ERR_COULD_NOT_HOST_HUB_ON_FARM
	ERR_FARM_MEMBER_HUB_ADMIN
	ERR_NULL_PASSWORD_LOCAL_ONLY
	ERR_NOT_ENOUGH_RIGHT
	ERR_LISTENER_NOT_FOUND
	ERR_LISTENER_ALREADY_EXISTS
	ERR_NOT_FARM_MEMBER
	ERR_CIPHER_NOT_SUPPORTED
	ERR_HUB_ALREADY_EXISTS
	ERR_TOO_MANY_HUBS
	ERR_LINK_ALREADY_EXISTS
	ERR_LINK_CANT_CREATE_ON_FARM
	ERR_LINK_IS_OFFLINE
	ERR_TOO_MANY_ACCESS_LIST
	ERR_TOO_MANY_USER
	ERR_TOO_MANY_GROUP
	ERR_GROUP_NOT_FOUND
	ERR_USER_ALREADY_EXISTS
	ERR_GROUP_ALREADY_EXISTS
	ERR_USER_AUTHTYPE_NOT_PASSWORD
	ERR_OLD_PASSWORD_WRONG
	ERR_LINK_CANT_DISCONNECT
	ERR_ACCOUNT_NOT_PRESENT
	ERR_ALREADY_ONLINE
	ERR_OFFLINE
	ERR_NOT_RSA_1024
	ERR_SNAT_CANT_DISCONNECT
	ERR_SNAT_NEED_STANDALONE
	ERR_SNAT_NOT_RUNNING
	ERR_SE_VPN_BLOCK
	ERR_BRIDGE_CANT_DISCONNECT
	ERR_LOCAL_BRIDGE_STOPPING
	ERR_LOCAL_BRIDGE_UNSUPPORTED
	ERR_CERT_NOT_TRUSTED
	ERR_PRODUCT_CODE_INVALID
	ERR_VERSION_INVALID
	ERR_CAPTURE_DEVICE_ADD_ERROR
	ERR_VPN_CODE_INVALID
	ERR_CAPTURE_NOT_FOUND
	ERR_LAYER3_CANT_DISCONNECT
	ERR_LAYER3_SW_EXISTS
	ERR_LAYER3_SW_NOT_FOUND
	ERR_INVALID_NAME
	ERR_LAYER3_IF_ADD_FAILED
	ERR_LAYER3_IF_DEL_FAILED
	ERR_LAYER3_IF_EXISTS
	ERR_LAYER3_TABLE_ADD_FAILED
	ERR_LAYER3_TABLE_DEL_FAILED
	ERR_LAYER3_TABLE_EXISTS
	ERR_BAD_CLOCK
	ERR_LAYER3_CANT_START_SWITCH
	ERR_CLIENT_LICENSE_NOT_ENOUGH
	ERR_BRIDGE_LICENSE_NOT_ENOUGH
	ERR_SERVER_CANT_ACCEPT
	ERR_SERVER_CERT_EXPIRES
	ERR_MONITOR_MODE_DENIED
	ERR_BRIDGE_MODE_DENIED
	ERR_IP_ADDRESS_DENIED
	ERR_TOO_MANT_ITEMS
	ERR_MEMORY_NOT_ENOUGH
	ERR_OBJECT_EXISTS
	ERR_FATAL
	ERR_SERVER_LICENSE_FAILED
	ERR_SERVER_INTERNET_FAILED
	ERR_CLIENT_LICENSE_FAILED
	ERR_BAD_COMMAND_OR_PARAM
	ERR_INVALID_LICENSE_KEY
	ERR_NO_VPN_SERVER_LICENSE
	ERR_NO_VPN_CLUSTER_LICENSE
	ERR_NOT_ADMINPACK_SERVER
	ERR_NOT_ADMINPACK_SERVER_NET
	ERR_BETA_EXPIRES
	ERR_BRANDED_C_TO_S
	ERR_BRANDED_C_FROM_S
	ERR_AUTO_DISCONNECTED
	ERR_CLIENT_ID_REQUIRED
	ERR_TOO_MANY_USERS_CREATED
	ERR_SUBSCRIPTION_IS_OLDER
	ERR_ILLEGAL_TRIAL_VERSION
	ERR_NAT_T_TWO_OR_MORE
	ERR_DUPLICATE_DDNS_KEY
	ERR_DDNS_HOSTNAME_EXISTS
	ERR_DDNS_HOSTNAME_INVALID_CHAR
	ERR_DDNS_HOSTNAME_TOO_LONG
	ERR_DDNS_HOSTNAME_IS_EMPTY
	ERR_DDNS_HOSTNAME_TOO_SHORT
	ERR_MSCHAP2_PASSWORD_NEED_RESET
	ERR_DDNS_DISCONNECTED
	ERR_SPECIAL_LISTENER_ICMP_ERROR
	ERR_SPECIAL_LISTENER_DNS_ERROR
	ERR_OPENVPN_IS_NOT_ENABLED
	ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE
	ERR_VPNGATE
	ERR_VPNGATE_CLIENT
	ERR_VPNGATE_INCLIENT_CANT_STOP
	ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE
	ERR_SUSPENDING
)

type _ErrorNo map[int]string

var ErrorNo = _ErrorNo{
	ERR_NO_ERROR:                             "No error",
	ERR_CONNECT_FAILED:                       "Connection to the server has failed",
	ERR_SERVER_IS_NOT_VPN:                    "The destination server is not a VPN server",
	ERR_DISCONNECTED:                         "The connection has been interrupted",
	ERR_PROTOCOL_ERROR:                       "Protocol error",
	ERR_CLIENT_IS_NOT_VPN:                    "Connecting client is not a VPN client",
	ERR_USER_CANCEL:                          "User cancel",
	ERR_AUTHTYPE_NOT_SUPPORTED:               "Specified authentication method is not supported",
	ERR_HUB_NOT_FOUND:                        "The HUB does not exist",
	ERR_AUTH_FAILED:                          "Authentication failure",
	ERR_HUB_STOPPING:                         "HUB is stopped",
	ERR_SESSION_REMOVED:                      "Session has been deleted",
	ERR_ACCESS_DENIED:                        "Access denied",
	ERR_SESSION_TIMEOUT:                      "Session times out",
	ERR_INVALID_PROTOCOL:                     "Protocol is invalid",
	ERR_TOO_MANY_CONNECTION:                  "Too many connections",
	ERR_HUB_IS_BUSY:                          "Too many sessions of the HUB",
	ERR_PROXY_CONNECT_FAILED:                 "Connection to the proxy server fails",
	ERR_PROXY_ERROR:                          "Proxy Error",
	ERR_PROXY_AUTH_FAILED:                    "Failed to authenticate on the proxy server",
	ERR_TOO_MANY_USER_SESSION:                "Too many sessions of the same user",
	ERR_LICENSE_ERROR:                        "License error",
	ERR_DEVICE_DRIVER_ERROR:                  "Device driver error",
	ERR_INTERNAL_ERROR:                       "Internal error",
	ERR_SECURE_DEVICE_OPEN_FAILED:            "The secure device cannot be opened",
	ERR_SECURE_PIN_LOGIN_FAILED:              "PIN code is incorrect",
	ERR_SECURE_NO_CERT:                       "Specified certificate is not stored",
	ERR_SECURE_NO_PRIVATE_KEY:                "Specified private key is not stored",
	ERR_SECURE_CANT_WRITE:                    "Write failure",
	ERR_OBJECT_NOT_FOUND:                     "Specified object can not be found",
	ERR_VLAN_ALREADY_EXISTS:                  "Virtual LAN card with the specified name already exists",
	ERR_VLAN_INSTALL_ERROR:                   "Specified virtual LAN card cannot be created",
	ERR_VLAN_INVALID_NAME:                    "Specified name of the virtual LAN card is invalid",
	ERR_NOT_SUPPORTED:                        "Unsupported",
	ERR_ACCOUNT_ALREADY_EXISTS:               "Account already exists",
	ERR_ACCOUNT_ACTIVE:                       "Account is operating",
	ERR_ACCOUNT_NOT_FOUND:                    "Specified account doesn't exist",
	ERR_ACCOUNT_INACTIVE:                     "Account is offline",
	ERR_INVALID_PARAMETER:                    "Parameter is invalid",
	ERR_SECURE_DEVICE_ERROR:                  "Error has occurred in the operation of the secure device",
	ERR_NO_SECURE_DEVICE_SPECIFIED:           "Secure device is not specified",
	ERR_VLAN_IS_USED:                         "Virtual LAN card in use by account",
	ERR_VLAN_FOR_ACCOUNT_NOT_FOUND:           "Virtual LAN card of the account can not be found",
	ERR_VLAN_FOR_ACCOUNT_USED:                "Virtual LAN card of the account is already in use",
	ERR_VLAN_FOR_ACCOUNT_DISABLED:            "Virtual LAN card of the account is disabled",
	ERR_INVALID_VALUE:                        "Value is invalid",
	ERR_NOT_FARM_CONTROLLER:                  "Not a farm controller",
	ERR_TRYING_TO_CONNECT:                    "Attempting to connect",
	ERR_CONNECT_TO_FARM_CONTROLLER:           "Failed to connect to the farm controller",
	ERR_COULD_NOT_HOST_HUB_ON_FARM:           "A virtual HUB on farm could not be created",
	ERR_FARM_MEMBER_HUB_ADMIN:                "HUB cannot be managed on a farm member",
	ERR_NULL_PASSWORD_LOCAL_ONLY:             "Accepting only local connections for an empty password",
	ERR_NOT_ENOUGH_RIGHT:                     "Right is insufficient",
	ERR_LISTENER_NOT_FOUND:                   "Listener can not be found",
	ERR_LISTENER_ALREADY_EXISTS:              "Listener already exists",
	ERR_NOT_FARM_MEMBER:                      "Not a farm member",
	ERR_CIPHER_NOT_SUPPORTED:                 "Encryption algorithm is not supported",
	ERR_HUB_ALREADY_EXISTS:                   "HUB already exists",
	ERR_TOO_MANY_HUBS:                        "Too many HUBs",
	ERR_LINK_ALREADY_EXISTS:                  "Link already exists",
	ERR_LINK_CANT_CREATE_ON_FARM:             "The link can not be created on the server farm",
	ERR_LINK_IS_OFFLINE:                      "Link is off-line",
	ERR_TOO_MANY_ACCESS_LIST:                 "Too many access list",
	ERR_TOO_MANY_USER:                        "Too many users",
	ERR_TOO_MANY_GROUP:                       "Too many Groups",
	ERR_GROUP_NOT_FOUND:                      "Group can not be found",
	ERR_USER_ALREADY_EXISTS:                  "User already exists",
	ERR_GROUP_ALREADY_EXISTS:                 "Group already exists",
	ERR_USER_AUTHTYPE_NOT_PASSWORD:           "Authentication method of the user is not a password authentication",
	ERR_OLD_PASSWORD_WRONG:                   "The user does not exist or the old password is wrong",
	ERR_LINK_CANT_DISCONNECT:                 "Cascade session cannot be disconnected",
	ERR_ACCOUNT_NOT_PRESENT:                  "Not completed configure the connection to the VPN server",
	ERR_ALREADY_ONLINE:                       "It is already online",
	ERR_OFFLINE:                              "It is offline",
	ERR_NOT_RSA_1024:                         "The certificate is not RSA 1024bit",
	ERR_SNAT_CANT_DISCONNECT:                 "SecureNAT session cannot be disconnected",
	ERR_SNAT_NEED_STANDALONE:                 "SecureNAT works only in stand-alone HUB",
	ERR_SNAT_NOT_RUNNING:                     "SecureNAT function is not working",
	ERR_SE_VPN_BLOCK:                         "Stopped by PacketiX VPN Block",
	ERR_BRIDGE_CANT_DISCONNECT:               "Bridge session can not be disconnected",
	ERR_LOCAL_BRIDGE_STOPPING:                "Bridge function is stopped",
	ERR_LOCAL_BRIDGE_UNSUPPORTED:             "Bridge feature is not supported",
	ERR_CERT_NOT_TRUSTED:                     "Certificate of the destination server can not be trusted",
	ERR_PRODUCT_CODE_INVALID:                 "Product code is different",
	ERR_VERSION_INVALID:                      "Version is different",
	ERR_CAPTURE_DEVICE_ADD_ERROR:             "Adding capture device failure",
	ERR_VPN_CODE_INVALID:                     "VPN code is different",
	ERR_CAPTURE_NOT_FOUND:                    "Capture device can not be found",
	ERR_LAYER3_CANT_DISCONNECT:               "Layer-3 session cannot be disconnected",
	ERR_LAYER3_SW_EXISTS:                     "L3 switch of the same already exists",
	ERR_LAYER3_SW_NOT_FOUND:                  "Layer-3 switch can not be found",
	ERR_INVALID_NAME:                         "Name is invalid",
	ERR_LAYER3_IF_ADD_FAILED:                 "Failed to add interface",
	ERR_LAYER3_IF_DEL_FAILED:                 "Failed to delete the interface",
	ERR_LAYER3_IF_EXISTS:                     "Interface that you specified already exists",
	ERR_LAYER3_TABLE_ADD_FAILED:              "Failed to add routing table",
	ERR_LAYER3_TABLE_DEL_FAILED:              "Failed to delete the routing table",
	ERR_LAYER3_TABLE_EXISTS:                  "Routing table entry that you specified already exists",
	ERR_BAD_CLOCK:                            "Time is queer",
	ERR_LAYER3_CANT_START_SWITCH:             "The Virtual Layer 3 Switch can not be started",
	ERR_CLIENT_LICENSE_NOT_ENOUGH:            "Client connection licenses shortage",
	ERR_BRIDGE_LICENSE_NOT_ENOUGH:            "Bridge connection licenses shortage",
	ERR_SERVER_CANT_ACCEPT:                   "Not Accept on the technical issues",
	ERR_SERVER_CERT_EXPIRES:                  "Destination VPN server has expired",
	ERR_MONITOR_MODE_DENIED:                  "Monitor port mode was rejected",
	ERR_BRIDGE_MODE_DENIED:                   "Bridge-mode or Routing-mode was rejected",
	ERR_IP_ADDRESS_DENIED:                    "Client IP address is denied",
	ERR_TOO_MANT_ITEMS:                       "Too many items",
	ERR_MEMORY_NOT_ENOUGH:                    "Out of memory",
	ERR_OBJECT_EXISTS:                        "Object already exists",
	ERR_FATAL:                                "A fatal error occurred",
	ERR_SERVER_LICENSE_FAILED:                "License violation has occurred on the server side",
	ERR_SERVER_INTERNET_FAILED:               "Server side is not connected to the Internet",
	ERR_CLIENT_LICENSE_FAILED:                "License violation occurs on the client side",
	ERR_BAD_COMMAND_OR_PARAM:                 "Command or parameter is invalid",
	ERR_INVALID_LICENSE_KEY:                  "License key is invalid",
	ERR_NO_VPN_SERVER_LICENSE:                "There is no valid license for the VPN Server",
	ERR_NO_VPN_CLUSTER_LICENSE:               "There is no cluster license",
	ERR_NOT_ADMINPACK_SERVER:                 "Not trying to connect to a server with the Administrator Pack license",
	ERR_NOT_ADMINPACK_SERVER_NET:             "Not trying to connect to a server with the Administrator Pack license (for .NET)",
	ERR_BETA_EXPIRES:                         "Destination Beta VPN Server has expired",
	ERR_BRANDED_C_TO_S:                       "Branding string of connection limit is different (Authentication on the server side)",
	ERR_BRANDED_C_FROM_S:                     "Branding string of connection limit is different (Authentication for client-side)",
	ERR_AUTO_DISCONNECTED:                    "VPN session is disconnected for a certain period of time has elapsed",
	ERR_CLIENT_ID_REQUIRED:                   "Client ID does not match",
	ERR_TOO_MANY_USERS_CREATED:               "Too many created users",
	ERR_SUBSCRIPTION_IS_OLDER:                "Subscription expiration date Is earlier than the build date of the VPN Server",
	ERR_ILLEGAL_TRIAL_VERSION:                "Many trial license is used continuously",
	ERR_NAT_T_TWO_OR_MORE:                    "There are multiple servers in the back of a global IP address in the NAT-T connection",
	ERR_DUPLICATE_DDNS_KEY:                   "DDNS host key duplicate",
	ERR_DDNS_HOSTNAME_EXISTS:                 "Specified DDNS host name already exists",
	ERR_DDNS_HOSTNAME_INVALID_CHAR:           "Characters that can not be used for the host name is included",
	ERR_DDNS_HOSTNAME_TOO_LONG:               "Host name is too long",
	ERR_DDNS_HOSTNAME_IS_EMPTY:               "Host name is not specified",
	ERR_DDNS_HOSTNAME_TOO_SHORT:              "Host name is too short",
	ERR_MSCHAP2_PASSWORD_NEED_RESET:          "Necessary that password is changed",
	ERR_DDNS_DISCONNECTED:                    "Communication to the dynamic DNS server is disconnected",
	ERR_SPECIAL_LISTENER_ICMP_ERROR:          "The ICMP socket can not be opened",
	ERR_SPECIAL_LISTENER_DNS_ERROR:           "Socket for DNS port can not be opened",
	ERR_OPENVPN_IS_NOT_ENABLED:               "OpenVPN server feature is not enabled",
	ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE:     "It is the type of user authentication that are not supported in the open source version",
	ERR_VPNGATE:                              "Operation on VPN Gate Server is not available",
	ERR_VPNGATE_CLIENT:                       "Operation on VPN Gate Client is not available",
	ERR_VPNGATE_INCLIENT_CANT_STOP:           "Can not be stopped if operating within VPN Client mode",
	ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE: "It is a feature that is not supported in the open source version",
	ERR_SUSPENDING:                           "System is suspending",
}

func RpcError(code int) error {
	return &ApiError{
		code:    code,
		message: ErrorNo[code],
	}
}

type ApiError struct {
	code    int
	message string
}

func (e ApiError) Error() string {
	return e.message
}
func (e ApiError) Code() int {
	return e.code
}
