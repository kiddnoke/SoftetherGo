package softetherApi

import (
	"log"
	"testing"
)

func TestAPI_HandShake(t *testing.T) {
	api := NewAPI("47.111.114.109", 443, "1212")
	if err := api.HandShake(); err != nil {
		log.Printf("HandShake Error: %v\n", err.Error())
		t.FailNow()
	}
}

func TestAPI_HandShakeFail(t *testing.T) {
	api := NewAPI("47.111.114.109", 443, "123")
	defer api.Disconnect()
	if err := api.HandShake(); err != nil {
		log.Printf("HandShake Error: %v\n", err.Error())
		t.Skipped()
	}
}
