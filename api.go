package softetherApi

import (
	"archive/zip"
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Response map[string]interface{}
type Request map[string][]interface{}

func keepalive(conn net.Conn) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	c.SetKeepAlive(true)
	c.SetKeepAlivePeriod(15 * time.Second)
}

type Connector interface {
	Connect() error
	Close() error
	GetSock() net.Conn
	Request(method, target string, body []byte, header http.Header) (Response, error)
	CallMethod(method string, request Request) (res Response, err error)
}

type APIConnect struct {
	host, port string
	Sock       net.Conn
}

func (c *APIConnect) Connect() error {
	Sock, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", c.host, c.port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	keepalive(Sock)
	c.Sock = Sock
	return nil
}

func (c *APIConnect) Close() error {
	return c.Sock.Close()
}

func (c *APIConnect) GetSock() net.Conn {
	return c.Sock
}

func (c *APIConnect) Request(method, target string, body []byte, headers http.Header) (res Response, err error) {
	if headers == nil {
		headers = globalHttpHeaders
	}
	header := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, target)
	for k, v := range headers {
		str := fmt.Sprintf("%s: %s\r\n", k, v[0])
		header += str
	}
	if headers.Get("Content-Length") == "" {
		str := fmt.Sprintf("%s: %d\r\n", "Content-Length", len(body))
		header += str
	}
	header += "\r\n"
	c.Sock.Write([]byte(header))
	n, err := c.Sock.Write(body)
	if err != nil {
		return nil, err
	}
	if n != len(body) {
		return
	}

	//
	var buf_length int
	r := bufio.NewReader(c.Sock)
	l, _, e := r.ReadLine()
	if e != nil {
		return nil, e
	}
	s := string(l[9:12])
	res = make(Response)
	res["code"], _ = strconv.Atoi(s)
	response_header := make(http.Header)

	for {
		line, _, e := r.ReadLine()
		if e != nil {
			return res, e
		}
		if string(line[:]) == "" {
			break
		}
		str_line := string(line[:])
		header := strings.Split(str_line, ": ")
		header_name := header[0]
		header_value := header[1]
		response_header.Set(header_name, header_value)
		if header_name == "Content-Length" {
			buf_length, _ = strconv.Atoi(header_value)
			res["length"] = buf_length
		}
	}
	res["header"] = response_header

	var buf []byte
	var sum int = 0
	for {
		tmpbuff := make([]byte, 4096)
		n, e = r.Read(tmpbuff)
		if e != nil {
			return nil, e
		}
		sum += n
		buf = append(buf, tmpbuff[:n]...)
		if buf_length == sum {
			break
		}
	}
	res["body"] = buf
	return res, nil
}

func (c *APIConnect) CallMethod(method string, request Request) (res Response, err error) {
	if request == nil {
		request = make(Request)
	}
	request["function_name"] = append(request["function_name"], method)
	payload_serialized := Protocol(nil).Serialize(request)
	os_socket := c.GetSock()
	proto_length := Protocol(nil)
	proto_length.SetInt(len(payload_serialized))
	os_socket.Write(proto_length.PayLoad)
	os_socket.Write(payload_serialized)

	data_lenth_buf := make([]byte, 4)
	n, _ := os_socket.Read(data_lenth_buf)
	if n != 4 {
		return nil, errors.New("api_call_wrong_data_length")
	}
	data_lenth_as_int := Protocol(data_lenth_buf).GetInt()
	var response_buffer []byte
	recv_sum := 0
	for {
		tmp_buf := make([]byte, 1024*4)
		n, err := os_socket.Read(tmp_buf)
		if n > 0 {
			recv_sum += n
			response_buffer = append(response_buffer, tmp_buf[:n]...)
		}
		if err != nil {
			if eo, ok := err.(*net.OpError); ok && eo.Timeout() || eo.Temporary() {
				goto HadRecvAllData
			}
		}
		if recv_sum == data_lenth_as_int {
			goto HadRecvAllData
		}
	}
HadRecvAllData:
	output, err := Protocol(response_buffer).Deserialize()
	if err != nil {
		return output, err
	}
	if err, ok := output["error"]; ok {
		if errno, ok := err.(interface{}).(int); ok && errno > 0 {
			return output, RpcError(errno)
		}
	}
	return output, nil
}

type API struct {
	Host            string
	Port            int
	Password        string
	Conn            Connector
	ConnectResponse map[string]interface{}
}

// API基础方法
func NewAPI(host string, port int, password string) *API {
	return &API{
		Conn:     &APIConnect{host, strconv.Itoa(port), nil},
		Host:     host,
		Port:     port,
		Password: password,
	}
}
func (a *API) Connect() (err error) {
	err = a.Conn.Connect()
	if err != nil {
		return err
	}
	res, err := a.Conn.Request("POST", "/vpnsvc/connect.cgi", []byte("VPNCONNECT"), nil)
	if err != nil {
		return err
	}
	if res["code"] != 200 {
		return errors.New("api_connect_non_200")
	}

	proto := Protocol(res["body"].([]byte))
	conn_response, err := proto.Deserialize()
	if _, ok := conn_response["random"]; ok == false {
		return errors.New("api_connect_missing_random")
	}
	a.ConnectResponse = conn_response
	return err
}
func (a *API) Authenticate(hub string) (err error) {
	random_from_svr := a.ConnectResponse["random"].(interface{}).(string)
	auth_payload := make(map[string][]interface{})
	auth_payload["method"] = append(auth_payload["method"], "admin")
	if hub != "" {
		auth_payload["hubname"] = append(auth_payload["hubname"], hub)
	}

	password_hasher := NewSha0Hash()
	password_hasher.Write([]byte(a.Password))
	hash_passwrod := password_hasher.Sum()

	secure_hasher := NewSha0Hash()
	secure_hasher.Write(hash_passwrod[:])
	secure_hasher.Write([]byte(random_from_svr))
	secure_password := secure_hasher.Sum()
	auth_payload["secure_password"] = append(auth_payload["secure_password"], secure_password)
	//
	proto := Protocol(nil)
	requst := proto.Serialize(auth_payload)

	authenticate_response, err := a.Conn.Request("POST", "/vpnsvc/vpn.cgi", requst, nil)
	if err != nil {
		return err
	}
	if authenticate_response["code"] != 200 {
		return RpcError(ERR_AUTH_FAILED)
	}
	if errs, ok := authenticate_response["error"]; ok {
		errno, _ := strconv.Atoi(errs.(string))
		return RpcError(errno)
	}
	proto = Protocol(authenticate_response["body"].([]byte))
	out, err := proto.Deserialize()
	if err != nil {
		return err
	}
	if err, ok := out["error"]; ok {
		if errno, _ := err.(interface{}).(int); errno > 0 {
			return RpcError(errno)
		}
	}
	return
}
func (a *API) Disconnect() {
	a.Conn.Close()
}
func (a *API) HandShake() error {
	if err := a.Connect(); err != nil {
		log.Printf("Connect Error: %v\n", err.Error())
		return err
	}
	if err := a.Authenticate(""); err != nil {
		log.Printf("Authenticate Error: %v\n", err.Error())
		return err
	}
	return nil
}

func (a *API) Test() {

}

func (a *API) GetCrl(name string, key int) (Response, error) {
	return a.Conn.CallMethod("GetCrl", Request{"HubName": {name}, "Key": {key}})
}

// Server Operation
func (a *API) SetServerPassword(password string) (Response, error) {
	password_hasher := NewSha0Hash()
	password_hasher.Write([]byte(password))
	hashed_password := password_hasher.Sum()
	return a.Conn.CallMethod("SetServerPassword", Request{"HashedPassword": {hashed_password}})
}
func (a *API) GetServerInfo() (Response, error) {
	return a.Conn.CallMethod("GetServerInfo", nil)
}
func (a *API) GetConfig() (Response, error) {
	return a.Conn.CallMethod("GetConfig", Request{})
}

// Hub Operation
func (a *API) CreateHub(name string, online bool, hub_type int) (Response, error) {
	if hub_type > HUB_TYPE_FARM_DYNAMIC {
		msg := fmt.Sprintf("hub_type[%d] is unspourts", hub_type)
		return nil, errors.New(msg)
	}

	req := Request{
		"HubName": {name},
		"Online": {func(b bool) int {
			if b {
				return 1
			} else {
				return 0
			}
		}(online)},
		"HubType": {hub_type},
	}
	return a.Conn.CallMethod("CreateHub", req)
}
func (a *API) ListHub() (Response, error) {
	return a.Conn.CallMethod("EnumHub", nil)
}
func (a *API) DeleteHub(name string) (Response, error) {
	return a.Conn.CallMethod("DeleteHub", Request{"HubName": {name}})
}
func (a *API) GetHub(name string) (Response, error) {
	return a.Conn.CallMethod("GetHub", Request{"HubName": {name}})
}
func (a *API) SetHub(name string, online bool, hub_type int) (Response, error) {
	return a.Conn.CallMethod("SetHub", Request{
		"HubName": {name},
		"Online":  {online},
		"HubType": {hub_type},
	})
}
func (a *API) GetHubStatus(name string) (Response, error) {
	return a.Conn.CallMethod("GetHubStatus", Request{"HubName": {name}})
}
func (a *API) SetHubOnline(name string) (Response, error) {
	return a.Conn.CallMethod("SetHubOnline", Request{"HubName": {name}})
}
func (a *API) GetHubAdminOptions(name string) (Response, error) {
	return a.Conn.CallMethod("GetHubAdminOptions", Request{"HubName": {name}})
}

// Group Operation
func (a *API) CreateGroup(hub, name, realname, note string) (Response, error) {
	return a.Conn.CallMethod("CreateGroup", Request{
		"HubName":  {hub},
		"Name":     {name},
		"RealName": {realname},
		"Note":     {note},
	})
}
func (a *API) SetGroup(hub, name string) (Response, error) {
	return a.Conn.CallMethod("SetGroup", Request{
		"HubName": {hub},
		"Name":    {name},
	})
}
func (a *API) GetGroup(hub, name string) (Response, error) {
	return a.Conn.CallMethod("GetGroup", Request{"HubName": {hub}, "Name": {name}})
}
func (a *API) DeleteGroup(hub, name string) (Response, error) {
	return a.Conn.CallMethod("DeleteGroup", Request{"HubName": {hub}, "Name": {name}})
}
func (a *API) ListGroup(hub string) (Response, error) {
	return a.Conn.CallMethod("EnumGroup", Request{"HubName": {hub}})
}

// User Operation
func (a *API) CreateUser(hub, useranme, password string) (Response, error) {
	hashKey := hashPassword(useranme, password)
	ntHashKey := genNtPasswordHash(password)
	payload := Request{
		"HubName":        {hub},
		"Name":           {useranme},
		"AuthType":       {AUTHTYPE_PASSWORD},
		"HashedKey":      {hashKey},
		"NtLmSecureHash": {ntHashKey},
	}
	return a.Conn.CallMethod("CreateUser", payload)
}
func (a *API) SetUserPassword(hub, useranme, password string) (Response, error) {
	hashKey := hashPassword(useranme, password)
	ntHashKey := genNtPasswordHash(password)
	payload := Request{
		"HubName":        {hub},
		"Name":           {useranme},
		"AuthType":       {AUTHTYPE_PASSWORD},
		"HashedKey":      {hashKey},
		"NtLmSecureHash": {ntHashKey},
	}
	return a.Conn.CallMethod("SetUser", payload)
}
func (a *API) DeleteUser(hub, name string) (Response, error) {
	return a.Conn.CallMethod("DeleteUser", Request{"HubName": {hub}, "Name": {name}})
}
func (a *API) GetUser(hub, name string) (Response, error) {
	return a.Conn.CallMethod("GetUser", Request{"HubName": {hub}, "Name": {name}})
}
func (a *API) ListUser(hub string) (Response, error) {
	return a.Conn.CallMethod("EnumUser", Request{"HubName": {hub}})
}
func (a *API) SetUserPolicy(hub, name string, MaxUpload, MaxDownload int) (Response, error) {
	payload := Request{
		"HubName":            {hub},
		"Name":               {name},
		"UsePolicy":          {1},
		"policy:Access":      {1},
		"policy:MaxUpload":   {MaxUpload},
		"policy:MaxDownload": {MaxDownload},
	}
	return a.Conn.CallMethod("SetUser", payload)
}

// SecureNat Operation
func (a *API) EnableSecureNat(name string) (Response, error) {
	return a.Conn.CallMethod("EnableSecureNAT", Request{"HubName": {name}})
}
func (a *API) DisableSecureNat(name string) (Response, error) {
	return a.Conn.CallMethod("DisableSecureNAT", Request{"HubName": {name}})
}
func (a *API) GetSecureNatStatus(name string) (Response, error) {
	return a.Conn.CallMethod("GetSecureNATStatus", Request{"HubName": {name}})
}
func (a *API) GetSecureNatOption(hubname string) (Response, error) {
	return a.Conn.CallMethod("GetSecureNATOption", Request{"RpcHubName": {hubname}})
}

func (a *API) SetSecureNatOption(hubname string, natoptions map[string]interface{}) (Response, error) {
	/*
		Ip 网卡的ip地址
		DhcpLeaseIPStart  dhcp分配ip开始
		DhcpLeaseIPEnd    dhcp分配ip结束
		DhcpGatewayAddress dhcp默认网关地址
		DhcpDnsServerAddress dhcp的dns服务器地址
	*/
	return a.Conn.CallMethod("SetSecureNATOption", Request{})
}

// OpenVPN Operation
func (a *API) SetOpenVpnSSTPConfig(enable_open_vpn, enable_sstp bool, open_vpn_port_list []int) (Response, error) {
	var booltoint8 = func(b bool) int {
		if b {
			return 1
		} else {
			return 0
		}
	}
	var intToString = func(input []int) []interface{} {
		var output []interface{}
		for _, i := range input {
			output = append(output, strconv.Itoa(i))
		}
		return output
	}
	req := Request{
		"EnableOpenVPN":   {booltoint8(enable_open_vpn)},
		"EnableSSTP":      {booltoint8(enable_sstp)},
		"OpenVPNPortList": intToString(open_vpn_port_list),
	}
	return a.Conn.CallMethod("SetOpenVpnSstpConfig", req)
}
func (a *API) GetOpenVpnSSTPConfig() (Response, error) {
	return a.Conn.CallMethod("GetOpenVpnSstpConfig", nil)
}
func (a *API) MakeOpenVpnConfigFile() (Response, error) {
	return a.Conn.CallMethod("MakeOpenVpnConfigFile", nil)
}
func (a *API) GetOpenVpnRemoteAccess() (string, error) {
	res, err := a.Conn.CallMethod("MakeOpenVpnConfigFile", nil)
	if err != nil {
		return "", err
	}
	var getRemoteAccess = func(stream string) (string, error) {
		zip_buffer := res["Buffer"].(string)
		zip_reader, err := zip.NewReader(strings.NewReader(zip_buffer), int64(len(zip_buffer)))
		if err != nil {
			return "", err
		} else {
			for _, File := range zip_reader.File {
				rc, err := File.Open()
				if err != nil {
					return "", err
				}
				if strings.Index(File.Name, "remote_access") > 0 {
					if stream, e := ioutil.ReadAll(rc); e == nil {
						return fmt.Sprintf("%s", stream), nil
					}
				}
			}
			return "", errors.New("there are not remote_access file")
		}
	}
	remoteaccess, err := getRemoteAccess(res["Buffer"].(string))
	if err == nil {
		return strings.Replace(remoteaccess, "proto udp\n", "proto tcp\n", -1), nil
	} else {
		return "", nil
	}
}

// IPSec Operation
func (a *API) IPsecEnable() (Response, error) {
	return a.Conn.CallMethod("IPSecEnable", Request{})
}
func (a *API) IPsecGet() (Response, error) {
	return a.Conn.CallMethod("GetIPsecServices", Request{})
}

// Cert Operation
func (a *API) GetServerCipher(str string) (Response, error) {
	return a.Conn.CallMethod("GetServerCipher", Request{"String": {str}})
}
func (a *API) GetServerCert() (string, error) {
	if out, err := a.Conn.CallMethod("GetServerCert", nil); err != nil {
		return "", err
	} else {
		var convert = func(input interface{}) []byte {
			if str, ok := input.(string); ok {
				return []byte(str)
			} else {
				return []byte("")
			}
		}
		cert := base64.StdEncoding.EncodeToString(convert(out["Cert"]))
		return cert, nil
	}
}

// DHCP Operation
func (a *API) ListDhcp(hubname string) (Response, error) {
	return a.Conn.CallMethod("EnumDHCP", Request{"HubName": {hubname}})
}

// DynamicDnsOperation
func (a *API) GetDDnsInternetSettng(hubname string) (Response, error) {
	return a.Conn.CallMethod("GetDDnsInternetSettng", Request{})
}
func (a *API) GetDDnsClientStatus() (Response, error) {
	return a.Conn.CallMethod("GetDDnsClientStatus", Request{})
}
func (a *API) GetDDnsHostName() (string, string, error) {
	out, err := a.GetDDnsClientStatus()
	if err != nil {
		return "", "", err
	}
	DDnsHostName := out["CurrentFqdn"].(string)
	Ipv4 := out["CurrentIPv4"].(string)
	return DDnsHostName, Ipv4, nil
}
