package softetherApi

import (
	"log"
	"testing"
)

func TestInetAtoN(t *testing.T) {
	ipint := InetAtoN("192.168.30.1")
	if ipint != 18786496 {
		t.FailNow()
	}
}
func TestInetNtoI(t *testing.T) {
	ipintarray := InetNtoI(18786496)
	log.Println(ipintarray)
}
func TestInetNtoA(t *testing.T) {
	ip := InetNtoA(18786496)
	if ip != "192.168.30.1" {
		t.FailNow()
	}
}
