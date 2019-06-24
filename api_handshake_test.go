package softetherApi

import (
	"log"
	"testing"
)

var a *API

func TestNewAPI(t *testing.T) {
	a = NewAPI("47.111.114.109", 443, "kiddNoke1")
}

func TestAPI_HandShake(t *testing.T) {
	if err := a.HandShake(); err != nil {
		log.Printf("HandShake Error: %v\n", err.Error())
		t.FailNow()
	}
}

func TestAPI_HandShakeFail(t *testing.T) {
	api := NewAPI("47.111.114.109", 443, "kiddNoke")
	defer api.Disconnect()
	if err := api.HandShake(); err != nil {
		log.Printf("HandShake Error: %v\n", err.Error())
		t.Skipped()
	}
}
