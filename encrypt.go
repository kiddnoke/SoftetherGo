package softetherApi

import (
	"golang.org/x/crypto/md4"
	"strings"
)

func NewPasswordAuthData(username, password string) []byte {
	buf := make([]byte, 0)
	sha0 := hashPassword(username, password)
	md4 := genNtPasswordHash(password)
	buf = append(buf, sha0...)
	buf = append(buf, md4...)
	return buf
}

func hashPassword(username, password string) (sha0 []byte) {
	USERNAME := strings.ToUpper(username)
	buf := password + USERNAME
	return Sha0Sum([]byte(buf))
}

func genNtPasswordHash(password string) (md []byte) {
	hasher := md4.New()
	tmp_size := len(password) * 2
	buf := make([]byte, tmp_size)
	for index, c := range password {
		buf[index*2] = byte(c)
	}
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func Sha0Sum(p []byte) []byte {
	sha0 := NewSha0Hash()
	sha0.Write(p)
	return sha0.Sum()
}
