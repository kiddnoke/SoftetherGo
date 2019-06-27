package softetherApi

import (
	"fmt"
	"log"
	"testing"
)

var a *API

func init() {
	a = NewAPI("47.111.114.109", 443, "vpn1")
	a.HandShake()
}

func TestAPI_GetServerInfo(t *testing.T) {
	if out, err := a.GetServerInfo(); err != nil {
		log.Printf("GetServerInfo Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("GetServerInfo :%v\n", out)
	}
}
func TestAPI_MakeOpenVpnConfigFile(t *testing.T) {
	if out, err := a.MakeOpenVpnConfigFile(); err != nil {
		log.Printf("MakeOpenVpnConfigFile Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("MakeOpenVpnConfigFile out[%v]", out)
	}
}
func TestAPI_GetOpenVpnRemoteAccess(t *testing.T) {
	if out, err := a.GetOpenVpnRemoteAccess(); err != nil {
		log.Printf("TestAPI_GetOpenVpnRemoteAccess Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("TestAPI_GetOpenVpnRemoteAccess\n%v", out)
	}
}
func TestAPI_ListUser(t *testing.T) {
	if out, err := a.ListUser("VPN"); err != nil {
		log.Printf("ListUser Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("ListUser :%v\n", out)
	}
}
func TestAPI_GetUser(t *testing.T) {
	if out, err := a.GetUser("VPN", "vpn"); err != nil {
		log.Printf("GetUser Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("GetUser :%v\n", out)
		log.Printf("CreatedTime[%v] UpdatedTime[%v]\n", out["CreatedTime"].(int64), out["UpdatedTime"].(int64))
		log.Printf("MaxUpload[%d] MaxDownload[%d]\n", out["policy:MaxUpload"].(int), out["policy:MaxDownload"].(int))
		log.Printf("HashedKey[% x] NtLmSecureHash[% x]\n", []byte(out["HashedKey"].(string)), []byte(out["NtLmSecureHash"].(string)))
		log.Printf("Recv.BroadcastBytes:%d Recv.UnicastBytes:%d ", out["Recv.BroadcastBytes"].(int64), out["Recv.UnicastBytes"].(int64))
		log.Printf("Send.BroadcastBytes:%d Send.UnicastBytes:%d ", out["Send.BroadcastBytes"].(int64), out["Send.UnicastBytes"].(int64))
	}
}

func TestAPI_ListHub(t *testing.T) {
	if out, err := a.ListHub(); err != nil {
		log.Printf("ListHub Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("ListHub :%v\n", out)
	}
}
func TestAPI_GetHub(t *testing.T) {
	if out, err := a.GetHub("VPN"); err != nil {
		log.Printf("GetHub Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("GetHub :%v\n", out)
		log.Printf("HashedKey[% x] NtLmSecureHash[% x]\n", []byte(out["HashedKey"].(string)), []byte(out["NtLmSecureHash"].(string)))

	}
}
func TestAPI_GetHubStatus(t *testing.T) {
	if out, err := a.GetHubStatus("VPN"); err != nil {
		log.Printf("GetHubStatus Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("GetHubStatus :%v\n", out)
	}
}
func TestAPI_GetServerCipher(t *testing.T) {
	if out, err := a.GetServerCipher(""); err != nil {
		log.Printf("GetServerCipher Error: %v\n", err)
		t.FailNow()
	} else {
		fmt.Printf("GetServerCipher Cipher:%v\n", out)
	}
}
func TestAPI_GetServerCert(t *testing.T) {
	if out, err := a.GetServerCert(); err != nil {
		log.Printf("GetServerCert Error: %v\n", err)
		t.FailNow()
	} else {
		log.Println(out)
	}
}
func TestAPI_GetOpenVpnSSTPConfig(t *testing.T) {
	if out, err := a.GetOpenVpnSSTPConfig(); err != nil {
		log.Printf("GetOpenVpnSSTPConfig Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetOpenVpnSSTPConfig %v\n", out)
	}
}
func TestAPI_SetOpenVpnSSTPConfig(t *testing.T) {
	if out, err := a.SetOpenVpnSSTPConfig(true, true, []int{2008}); err != nil {
		log.Printf("SetOpenVpnSSTPConfig Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("SetOpenVpnSSTPConfig %v\n", out)
	}
}
func TestAPI_GetSecureNatStatus(t *testing.T) {
	if out, err := a.GetSecureNatStatus("VPN"); err != nil {
		log.Printf("GetSecureNatStatus Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetSecureNatStatus %v\n", out)
	}
}
func TestAPI_GetSecureNatOption(t *testing.T) {
	if out, err := a.GetSecureNatOption("vpn2"); err != nil {
		log.Printf("GetSecureNatOption Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetSecureNatOption %v\n", out)
	}
}
func TestAPI_SetSecureNatOption(t *testing.T) {
	if out, err := a.SetSecureNatOption("vpn2", map[string]interface{}{}); err != nil {
		log.Printf("SetSecureNatOption Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("SetSecureNatOption %v\n", out)
	}
}
func TestAPI_SetServerPassword(t *testing.T) {
	if out, err := a.SetServerPassword("vpn1"); err != nil {
		log.Printf("SetServerPassword Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("SetServerPassword %v\n", out)
	}
}
func TestAPI_GetConfig(t *testing.T) {
	if out, err := a.GetConfig(); err != nil {
		log.Printf("GetConfig Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetConfig %v\n", out)
	}
}
func TestAPI_GetHubAdminOptions(t *testing.T) {
	if out, err := a.GetHubAdminOptions("VPN"); err != nil {
		log.Printf("GetHubAdminOptions Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetHubAdminOptions %v\n", out)
	}
}
func TestAPI_CreateUser(t *testing.T) {
	if out, err := a.CreateUser("VPN", "zhangsen3", "VPN"); err != nil {
		log.Printf("CreateUser Error: %v", err)
		t.FailNow()
	} else {
		log.Println("CreateUser :", out)
	}
}
func TestAPI_Create(t *testing.T) {
	//
	if out, err := a.CreateHub("golang", true, HUB_TYPE_STANDALONE); err != nil {
		if e, ok := err.(*ApiError); ok && e.Code() != ERR_HUB_ALREADY_EXISTS {
			log.Printf("CreateHub Error: %v\n", err)
			t.FailNow()
		}
	} else {
		log.Printf("HashedPassword[%s] SecurePassword[%s]\n", out["HashedPassword"], out["SecurePassword"])
	}
	//defer a.DeleteHub("golang")
	if out, err := a.EnableSecureNat("golang"); err != nil {
		log.Printf("EnableSecureNat Error: %v", out)
		t.FailNow()
	} else {
		log.Println("EnableSecureNat :", out)
	}
	//
	if out, err := a.CreateUser("golang", "golang", "golang"); err != nil {
		if e, ok := err.(*ApiError); ok && e.Code() != ERR_USER_ALREADY_EXISTS {
			log.Printf("CreateUser Error: %v\n", err)
			t.FailNow()
		}
	} else {
		log.Printf("CreateUser %v\n", out)
		log.Printf("HashedKey[% x] NtLmSecureHash[% x]\n", []byte(out["HashedKey"].(string)), []byte(out["NtLmSecureHash"].(string)))
	}

	//defer a.DeleteUser("golang", "golang")
	//
	//if out, err := a.SetUserPassword("golang", "golang", "golang22"); err != nil {
	//	log.Printf("SetUserPassword Error: %v\n", err)
	//	t.FailNow()
	//} else {
	//	log.Printf("SetUserPassword : %v\n", out)
	//}
}
func TestAPI_ListDhcp(t *testing.T) {
	//
	if out, err := a.ListDhcp("golang"); err != nil {
		log.Printf("ListDhcp Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("ListDhcp : %v\n", out)
	}
}
func TestAPI_SetUserPolicy(t *testing.T) {
	if out, err := a.SetUserPolicy("VPN", "vpn", 3000000, 4000000); err != nil {
		log.Printf("SetUserPolicy Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("SetUserPolicy %v", out)
	}
	if out, err := a.GetUser("VPN", "vpn"); err != nil {
		log.Printf("GetUser Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetUser %v", out)
	}
}
func TestAPI_GetDDnsInternetSettng(t *testing.T) {
	if out, err := a.GetDDnsInternetSettng("VPN"); err != nil {
		log.Printf("GetDDnsInternetSettng Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetDDnsInternetSettng %v", out)
	}
}
func TestAPI_GetDDnsClientStatus(t *testing.T) {
	if out, err := a.GetDDnsClientStatus(); err != nil {
		log.Printf("GetDDnsClientStatus Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetDDnsClientStatus %v", out)
	}
}
func TestAPI_GetDDnsHostName(t *testing.T) {
	if host, address, err := a.GetDDnsHostName(); err != nil {
		log.Printf("GetDDnsHostName Error: %v\n", err)
		t.FailNow()
	} else {
		log.Printf("GetDDnsHostName[%s] Address[%s]", host, address)
	}
}
