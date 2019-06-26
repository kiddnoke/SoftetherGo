package softetherApi

import (
	"log"
	"testing"
)

//golang golang HashedKey[a1 97 d2 e7 74 f5 e0 1c 2e 98 e8 d7 e2 4e e3 48 1f 57 f8 fb] NtLmSecureHash[6d 90 b3 9f fa 90 be f9 e5 f9 bd b8 6b 6a 34 12]
func Test_hashPassword(t *testing.T) {
	hashed := hashPassword("golang", "golang")
	log.Printf("HashedKey[% x]", hashed)
}

func Test_genNtPasswordHash(t *testing.T) {
	hashed := genNtPasswordHash("golang")
	log.Printf("NtLmSecureHash[% x]", hashed)
}
