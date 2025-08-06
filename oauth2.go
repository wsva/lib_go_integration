package lib

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	wl_net "github.com/wsva/lib_go/net"
	wl_uuid "github.com/wsva/lib_go/uuid"
)

const (
	OAuth2LoginPath    = "/oauth2/login"
	OAuth2CallbackPath = "/oauth2/callback"
)

type UserInfo struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (u *UserInfo) String() string {
	jsonBytes, _ := json.Marshal(u)
	return string(jsonBytes)
}

type IntrospectResponse struct {
	Active  bool   `json:"active"`
	Subject string `json:"sub"`
}

type OAuth2 struct {
	Context       context.Context
	Config        *oauth2.Config
	State         string
	CodeVerifier  string
	CodeChallenge string
	UserinfoURL   string
	IntrospectURL string
	ReturnTo      string
}

// redirect to oauth2/authorize
func (o *OAuth2) HandleLogin(w http.ResponseWriter, r *http.Request) {
	return_to := r.FormValue("return_to")
	return_to, _ = url.PathUnescape(return_to)
	o.ReturnTo = return_to

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

func (o *OAuth2) HandleCallback(w http.ResponseWriter, r *http.Request) {
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

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "failed decoding user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	SetCookieToken(w, "userinfo", userInfo.String(), int(365*24*time.Hour/time.Second))

	http.Redirect(w, r, o.ReturnTo, http.StatusSeeOther)
}

func VerifyToken(r *http.Request, client *http.Client, introspectURL string) error {
	tokenString, err := ParseTokenFromRequest(r)
	if err != nil {
		return err
	}

	reqBody := strings.NewReader("token=" + tokenString)
	req, _ := http.NewRequest("POST", introspectURL, reqBody)
	//req.SetBasicAuth(o.Config.ClientID, "client_secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return errors.New("request introspect error")
	}
	defer resp.Body.Close()

	var result IntrospectResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil || !result.Active {
		return errors.New("invalid token")
	}
	return nil
}

type AuthService struct {
	ClientID      string `json:"ClientID"`
	AuthorizeURL  string `json:"AuthorizeURL"`
	TokenURL      string `json:"TokenURL"`
	UserInfoURL   string `json:"UserInfoURL"`
	IntrospectURL string `json:"IntrospectURL"`
}

func (a *AuthService) OAuth2(client *http.Client, state string) *OAuth2 {
	verifier := wl_uuid.New()
	s256 := sha256.Sum256([]byte(verifier))
	// trim padding, but why?
	challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")

	return &OAuth2{
		Context: context.WithValue(context.Background(), oauth2.HTTPClient, client),
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
	}
}

// user state as key
type OAuth2Map struct {
	Map map[string]*OAuth2
}

func (o *OAuth2Map) Add(auth *AuthService, client *http.Client) *OAuth2 {
	if o.Map == nil {
		o.Map = make(map[string]*OAuth2)
	}
	state := wl_uuid.New()
	oauth2 := auth.OAuth2(client, state)
	o.Map[state] = oauth2
	return oauth2
}

func (o *OAuth2Map) Get(state string) (*OAuth2, error) {
	if o.Map == nil {
		o.Map = make(map[string]*OAuth2)
	}
	oauth2, ok := o.Map[state]
	if !ok {
		return nil, errors.New("invalid state")
	}
	return oauth2, nil
}

func (o *OAuth2Map) Delete(state string) {
	if o.Map == nil {
		o.Map = make(map[string]*OAuth2)
	}
	delete(o.Map, state)
}
