package lib

import (
	"encoding/json"
	"net/http"
	"time"

	wl_crypto "github.com/wsva/lib_go/crypto"
)

const (
	InternalKeyHeader = "IK"
)

type InternalKey struct {
	UnixTime int64 `json:"UnixTime"`
}

func (k *InternalKey) JSONString() string {
	jsonBytes, _ := json.Marshal(*k)
	return string(jsonBytes)
}

func GenerateInternalKey(aesKey, aesIV string) string {
	key := &InternalKey{
		UnixTime: time.Now().Unix(),
	}
	ctext, err := wl_crypto.AES256Encrypt(aesKey, aesIV, key.JSONString())
	if err != nil {
		return "error"
	}
	return ctext
}

func CheckInternalKey(r *http.Request, aesKey, aesIV string) bool {
	ik := r.Header.Get(InternalKeyHeader)
	text, err := wl_crypto.AES256Decrypt(aesKey, aesIV, ik)
	if err != nil {
		return false
	}
	var key InternalKey
	err = json.Unmarshal([]byte(text), &key)
	if err != nil {
		return false
	}
	return time.Now().Unix()-key.UnixTime < 60
}
