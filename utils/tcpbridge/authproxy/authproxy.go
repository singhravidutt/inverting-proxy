package authproxy

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"time"
)

var (
	port    = flag.Int("port", 8080, "the port to serve on")
	backend = flag.String("backend", "", "url of the backend server")
)

// configHelperResp corresponds to the JSON output of the `gcloud config-helper` command.
type configHelperResp struct {
	Credential struct {
		AccessToken string `json:"access_token"`
		TokenExpiry string `json:"token_expiry"`
	} `json:"credential"`
}

func gcloudToken() (*oauth2.Token, error) {
	cmd := exec.Command("gcloud", "config", "config-helper", "--format=json")
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running the config-helper command: %w", err)
	}
	var r configHelperResp
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("parsing the config-helper output: %w", err)
	}
	expiryTime, err := time.Parse(time.RFC3339, r.Credential.TokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("failure parsing the token expiry time: %w", err)
	}
	return &oauth2.Token{
		AccessToken: r.Credential.AccessToken,
		Expiry:      expiryTime,
	}, nil
}

func UpdateAuthHeader(h http.Header) {
	tokenSource := oauth2.ReuseTokenSource(nil, tokenSourceFunc(gcloudToken))
	token, err := tokenSource.Token()
	if err != nil {
		log.Printf("Failure while updating auth header for connection %v", err)
		return
	}
	log.Printf("token type %v", token.Type())
	h.Set("Authorization", token.Type()+" "+token.AccessToken)
}
func GetAuthToken() (*oauth2.Token, error) {
	tokenSource := oauth2.ReuseTokenSource(nil, tokenSourceFunc(gcloudToken))
	return tokenSource.Token()
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (tsf tokenSourceFunc) Token() (*oauth2.Token, error) {
	return tsf()
}
func proxy(backendURL *url.URL) http.Handler {
	tokenSource := oauth2.ReuseTokenSource(nil, tokenSourceFunc(gcloudToken))
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := tokenSource.Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token.SetAuthHeader(r)
		r.Host = backendURL.Host
		r.URL.Scheme = backendURL.Scheme
		fmt.Printf("Forwarding request: %+v\n", r)
		proxy.ServeHTTP(w, r)
	})
}
