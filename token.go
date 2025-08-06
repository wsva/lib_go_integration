package lib

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

func SetCookieToken(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
		Expires:  time.Now().Add(7 * 24 * time.Hour), // longer expiration
	})
}

func DeleteCookieToken(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // this deletes the cookie
	})
}

func ParseTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("access_token")
	if err == nil {
		return cookie.Value, nil
	}
	token := r.Header.Get("Authorization")
	if len(token) > 6 && strings.ToUpper(token[0:7]) == "BEARER " {
		return token[7:], nil
	}
	return "", errors.New("no token found")
}
