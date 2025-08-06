package lib

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"

	wl_http "github.com/wsva/lib_go/http"
	wl_net "github.com/wsva/lib_go/net"
	wl_uuid "github.com/wsva/lib_go/uuid"
)

const (
	OAuth2LoginPath    = "/oauth2/login"
	OAuth2CallbackPath = "/oauth2/callback"
)

type OAuth2 struct {
	Context       context.Context
	Config        *oauth2.Config
	State         string
	CodeVerifier  string
	CodeChallenge string
	UserinfoURL   string
	IntrospectURL string
}

// redirect to oauth2/authorize
func (o *OAuth2) GetHandleLogin() func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		thisHost := wl_net.GetSchemaAndHost(r)
		o.Config.RedirectURL = fmt.Sprintf("%v%v", thisHost, OAuth2CallbackPath)

		authCodeURL := o.Config.AuthCodeURL(o.State, oauth2.AccessTypeOffline)
		authURL, _ := url.Parse(authCodeURL)
		query := authURL.Query()
		query.Set("code_challenge", o.CodeChallenge)
		query.Set("code_challenge_method", "S256")
		authURL.RawQuery = query.Encode()

		http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
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
		token, err := o.Config.Exchange(o.Context, code, oauth2.SetAuthURLParam("code_verifier", o.CodeVerifier))
		if err != nil {
			http.Error(w, "code exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		SetCookieToken(w, "access_token", token.AccessToken, int(token.ExpiresIn))
		SetCookieToken(w, "refresh_token", token.RefreshToken, int(token.ExpiresIn))

		// get user info using token
		client := o.Config.Client(o.Context, token)
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

func (o *OAuth2) VerifyToken(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return errors.New("missing access token")
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	reqBody := strings.NewReader("token=" + tokenString)
	req, _ := http.NewRequest("POST", o.IntrospectURL, reqBody)
	req.SetBasicAuth(o.Config.ClientID, "client_secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.New("request introspect error")
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	active, ok := result["active"].(bool)
	if !ok || !active {
		return errors.New("invalid token")
	}
	return nil
}

func (o *OAuth2) GetHandleVerifyToken() func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if err := o.VerifyToken(r); err != nil {
			wl_http.RespondError(w, err)
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

func (a *AuthService) OAuth2(caCrtFile string) (*OAuth2, error) {
	caCert, err := os.ReadFile(caCrtFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, errors.New("add ca to cert pool error")
	}

	verifier := wl_uuid.New()
	s256 := sha256.Sum256([]byte(verifier))
	// trim padding, but why?
	challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")

	return &OAuth2{
		Context: context.WithValue(
			context.Background(),
			oauth2.HTTPClient,
			&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: caCertPool,
					},
				},
				Timeout: 10 * time.Second,
			},
		),
		Config: &oauth2.Config{
			ClientID:     a.ClientID,
			ClientSecret: "current_no_use",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  a.AuthorizeURL,
				TokenURL: a.TokenURL,
			},
		},
		State:         wl_uuid.New(),
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		UserinfoURL:   a.UserInfoURL,
		IntrospectURL: a.IntrospectURL,
	}, nil
}
