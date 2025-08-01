package lib

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	wl_crypto "github.com/wsva/lib_go/crypto"
	wl_http "github.com/wsva/lib_go/http"
)

const (
	SUCCESS = "SUCCESS"
)

func GenerateToken(key, iv string) (string, error) {
	num, err := cryptorand.Int(cryptorand.Reader, big.NewInt(100000))
	if err != nil {
		return "", nil
	}
	randString := fmt.Sprint(time.Now().UnixNano(), num.String())
	return wl_crypto.AES256SaltEncrypt(key, iv, randString)
}

func SetCookieToken(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:  "token",
		Value: token,
		Path:  "/",
		//以秒为单位
		MaxAge:  int(365 * 24 * time.Hour / time.Second),
		Expires: time.Now().AddDate(1, 0, 0),
	}
	http.SetCookie(w, cookie)
}

func ParseTokenFromHeader(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	if len(token) > 6 && strings.ToUpper(token[0:7]) == "BEARER " {
		return token[7:], nil
	}
	return token, nil
}

func ParseTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return "", errors.New("no token found in cookie")
	}
	//cookie.Expires 输出一下即可知道，不能正确获取到
	/* if cookie.Expires.Before(time.Now()) {
		return "", errors.New("token has expired")
	} */
	return cookie.Value, nil
}

// parse cookie first
func ParseTokenFromRequest(r *http.Request) (string, error) {
	token, err := ParseTokenFromCookie(r)
	if err == nil {
		return token, nil
	} else {
		fmt.Println(err)
	}
	token, err = ParseTokenFromHeader(r)
	if err == nil {
		return token, nil
	} else {
		fmt.Println(err)
	}
	return "", errors.New("no token found")
}

func CheckAndRefreshToken(addressAccount, caCrtFile, token string) error {
	client := wl_http.HttpsClient{
		ServerAddress: addressAccount + "/checkandrefreshtoken",
		Method:        http.MethodPost,
		Data:          strings.NewReader(token),
		CACrtFile:     caCrtFile,
	}
	resp, err := client.DoRequest(false)
	if err != nil {
		return err
	}
	if string(resp) == SUCCESS {
		return nil
	}
	return errors.New("verify failed: " + string(resp))
}
