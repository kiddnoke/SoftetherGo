package softetherApi

import (
	"fmt"
	"math/big"
	"net"
)

func InetNtoA(ip int64) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
func InetNtoI(ip int64) (b [4]int) {
	b[0] = int(byte(ip))
	b[1] = int(byte(ip >> 8))
	b[2] = int(byte(ip >> 16))
	b[3] = int(byte(ip >> 24))
	return
}
func InetAtoN(ip string) int64 {
	ret := big.NewInt(0)
	v := net.ParseIP(ip).To4()
	ret.SetBytes([]byte{v[3], v[2], v[1], v[0]})
	return ret.Int64()
}
