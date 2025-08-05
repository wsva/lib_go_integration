package lib

import (
	"context"
	"encoding/json"
	"net/http"

	"golang.org/x/oauth2"

	wl_uuid "github.com/wsva/lib_go/uuid"
)

type OAuth2 struct {
	Config      *oauth2.Config
	State       string
	UserinfoURL string
}

func NewOAuth2(client_id, authorizeUrl, tokenUrl, userinfoUrl string) *OAuth2 {
	return &OAuth2{
		Config: &oauth2.Config{
			ClientID:     client_id,
			ClientSecret: "current_no_use",
			RedirectURL:  "/oauth2/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  authorizeUrl,
				TokenURL: tokenUrl,
			},
		},
		State:       wl_uuid.New(),
		UserinfoURL: userinfoUrl,
	}
}

// redirect to oauth2/authorize
func (o *OAuth2) GetHandleLogin() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		url := o.Config.AuthCodeURL(o.State, oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (o *OAuth2) GetHandleCallback() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
