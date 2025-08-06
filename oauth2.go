package lib

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	wl_http "github.com/wsva/lib_go/http"
	wl_uuid "github.com/wsva/lib_go/uuid"
)

type OAuth2 struct {
	Config        *oauth2.Config
	State         string
	UserinfoURL   string
	IntrospectURL string
}

// redirect to oauth2/authorize
func (o *OAuth2) GetHandleLogin() func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		url := o.Config.AuthCodeURL(o.State, oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (o *OAuth2) GetHandleCallback() func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		state := r.FormValue("state")
		if state != o.State {
			http.Error(w, "invalid oauth state", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "code not found", http.StatusBadRequest)
			return
		}

		// get token using code
		token, err := o.Config.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, "code exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// get user info using token
		client := o.Config.Client(context.Background(), token)
		resp, err := client.Get(o.UserinfoURL)
		if err != nil {
			http.Error(w, "failed getting user info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var userInfo map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			http.Error(w, "failed decoding user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}
}

func (o *OAuth2) GetHandleVerifyToken() func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			wl_http.RespondError(w, "missing access token")
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		reqBody := strings.NewReader("token=" + tokenString)
		req, _ := http.NewRequest("POST", o.IntrospectURL, reqBody)
		req.SetBasicAuth(o.Config.ClientID, "client_secret")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			wl_http.RespondError(w, "request introspect error")
			return
		}
		defer resp.Body.Close()

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		active, ok := result["active"].(bool)
		if !ok || !active {
			wl_http.RespondError(w, "invalid token")
			return
		}

		next(w, r)
	}
}

type AuthService struct {
	ClientID      string `json:"ClientID"`
	AuthorizeURL  string `json:"AuthorizeURL"`
	TokenURL      string `json:"TokenURL"`
	UserInfoURL   string `json:"UserInfoURL"`
	IntrospectURL string `json:"IntrospectURL"`
}

func (a *AuthService) OAuth2() *OAuth2 {
	return &OAuth2{
		Config: &oauth2.Config{
			ClientID:     a.ClientID,
			ClientSecret: "current_no_use",
			RedirectURL:  "/oauth2/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  a.AuthorizeURL,
				TokenURL: a.TokenURL,
			},
		},
		State:         wl_uuid.New(),
		UserinfoURL:   a.UserInfoURL,
		IntrospectURL: a.IntrospectURL,
	}
}
