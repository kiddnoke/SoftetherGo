package softetherApi

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"log"
	"testing"
)

func TestNewSha0Hash(t *testing.T) {
	NewSha0Hash()
}
func TestSHA0_Update(t *testing.T) {
	hasher := NewSha0Hash()
	if n := hasher.Write([]byte("kiddNoke1")); n != 9 {
		t.FailNow()
	}

}
func TestSHA0_Sum(t *testing.T) {
	hasher := NewSha0Hash()
	if n := hasher.Write([]byte("1")); n != 1 {
		t.FailNow()
	}
	hashed_password := hasher.Sum()
	log.Printf("authpassword %s", base64.StdEncoding.EncodeToString(hashed_password))
}
func TestSHA1_Sum(t *testing.T) {
	hasher := sha1.New()
	if n, _ := hasher.Write([]byte("1")); n != 1 {
		t.FailNow()
	}
	hashed_password := hasher.Sum(nil)
	log.Printf("authpassword %s", base64.StdEncoding.EncodeToString(hashed_password))
}
func Test_MD5(t *testing.T) {
	/*
		byte AuthNtLmSecureHash aZQ8XmO00sEE27zBUTi3Kw==
		byte AuthPassword ya9vjuS1VlkxSnvRTVsJwEAptHo=
	*/

	hasher := md5.New()
	if n, _ := hasher.Write([]byte("1")); n != 1 {
		t.FailNow()
	}
	hashed_password := hasher.Sum(nil)
	log.Printf("AuthNtLmSecureHash %s", base64.StdEncoding.EncodeToString(hashed_password))
}
