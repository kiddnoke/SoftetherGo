package softetherApi

import "net/http"

var globalHttpHeaders = http.Header{
	"Keep-Alive":   {"timeout=15; max=19"},
	"Connection":   {"Keep-Alive"},
	"Content-Type": {"application/octet-stream"},
}

const (
	AUTHTYPE_ANONYMOUS = iota // Anonymous authentication
	AUTHTYPE_PASSWORD         // Password authentication
	AUTHTYPE_USERCERT         // User certificate authentication
	AUTHTYPE_ROOTCERT         // Root certificate which is issued by trusted Certificate Authority
	AUTHTYPE_RADIUS           // Radius authentication
	AUTHTYPE_NT               // Windows NT authentication
	AUTHTYPE_TICKET           // Ticket authentication
)

// Type of HUB
const (
	HUB_TYPE_STANDALONE   = 0 // Stand-alone HUB
	HUB_TYPE_FARM_STATIC  = 1 // Static HUB
	HUB_TYPE_FARM_DYNAMIC = 2 // Dynamic HUB
)
