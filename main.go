package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/pkg/browser"
	"io"
	"log"
  "log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

/*
 * https://pkg.go.dev/encoding/json
 */

type OidcMetadata struct {
	Issuer                            string   `json:"issuer,omitempty"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	BackchannelAuthenticationEndpoint string   `json:"backchannel_authentication_endpoint,omitempty"`
	MtlsEndpointAliases               struct{} `json:"mtls_endpoint_aliases,omitempty"`
}

func FormatJson(data []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", "  ")
	if err == nil {
		return out.Bytes(), err
	}
	return data, nil
}

func Discover(provider string) (OidcMetadata, error) {
	metaDataUrl := fmt.Sprintf("%s/.well-known/openid-configuration", provider)
	req, err := http.NewRequest("GET", metaDataUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", `application/json`)
	client := http.Client{Timeout: time.Duration(5) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		closeErr := Body.Close()
		if closeErr != nil {
			log.Fatal(err)
		}
	}(resp.Body)
  slog.Info("Got response!")
  slog.Info(fmt.Sprintf("Status code: %d", resp.StatusCode))
	body, err := io.ReadAll(resp.Body)
	var metadata OidcMetadata
	if prettyJson, err := FormatJson(body); err != nil {
		log.Fatal(err)
	} else {
    slog.Info(fmt.Sprintf("Body : %s", string(prettyJson)))
	}
	err = json.Unmarshal(body, &metadata)
	return metadata, err
}

func CreateBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func CreateCallbackUrl(callbackPort string) string {
	return fmt.Sprintf("%s:%s", "http://localhost", callbackPort)
}

func GetToken(clientId string, clientSecret string, tokenUrl string, code string, callbackPort string, wg *sync.WaitGroup) {
	redirectUri := CreateCallbackUrl(callbackPort)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectUri)

	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatal("Failed to create token request", err)
	}

	req.Header.Add("Authorization", "Basic "+CreateBasicAuth(clientId, clientSecret))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, _ := httputil.DumpRequest(req, true)
  slog.Info(fmt.Sprintf("Authorization response: %s", string(res)))

	client := http.Client{Timeout: time.Duration(30) * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)

  slog.Info(fmt.Sprintf("Got token response with status: %d\n", resp.StatusCode))
	body, err := io.ReadAll(resp.Body)

	if prettyJson, err := FormatJson(body); err != nil {
		log.Fatal(err)
	} else {
    slog.Info(fmt.Sprintf("JWT\n%s\n", string(prettyJson)))
	}

	time.Sleep(10 * time.Second)
	wg.Done()
}

func CallbackServer(clientId string, clientSecret string, tokenEndpoint string, callbackPort string, wg *sync.WaitGroup) {
  wg.Add(1)

  defer wg.Done()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    slog.Info("Got a callback request from the OIDC provider")
		res, err := httputil.DumpRequest(r, true)
		if err != nil {
      http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
      return
		}
    slog.Info(fmt.Sprintf("Request query: %s", r.URL.Query()))
    slog.Info(fmt.Sprintf("Response: %s", string(res)))
		code := r.URL.Query().Get("code")
    slog.Info(fmt.Sprintf("Authorization code: %s", code))
    w.WriteHeader(http.StatusOK)
		if err := r.Body.Close(); err != nil {
      http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
      return
		}
    log.Println("Start getting an access token via the token endpoint")
		GetToken(clientId, clientSecret, tokenEndpoint, code, callbackPort, wg)
	})

	err := http.ListenAndServe(fmt.Sprintf(":%s", callbackPort), nil)
	if errors.Is(err, http.ErrServerClosed) {
    slog.Info("Server closed\n")
	} else if err != nil {
		log.Fatal(err)
	}
}

func CreateAuthzUrl(endpoint string, clientId string, state string, redirectUri string) string {
	return fmt.Sprintf("%s?response_type=code&client_id=%s&state=%s&redirect_uri=%s",
		endpoint, clientId, state, redirectUri)
}

func Authenticate(clientId string, endpoint string, callbackPort string) {
	if clientId == "" {
		log.Fatal("The argument clientId must not be null nor empty")
	}
	state := uuid.New().String()
	callbackUrl := CreateCallbackUrl(callbackPort)
	authzUrl := CreateAuthzUrl(endpoint, clientId, state, url.QueryEscape(callbackUrl))
  slog.Info(fmt.Sprintf("Authorization URL: %s", authzUrl))
	err := browser.OpenURL(authzUrl)
	if err != nil {
		log.Fatal("Error when opening the Web browser with the authorization code grant request", err)
	}
}

func main() {
  log.SetFlags(log.Ldate | log.Lmicroseconds)
  slog.SetLogLoggerLevel(slog.LevelDebug)

	var wg sync.WaitGroup

	provider := os.Getenv("OIDC_PROVIDER")

	if provider == "" {
		log.Fatal("The environment variable OIDC_PROVIDER is not set")
	}

	clientId := os.Getenv("OIDC_CLIENT_ID")

	if clientId == "" {
		log.Fatal("The environment variable OIDC_CLIENT_ID is not set")
	}

	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	if clientSecret == "" {
		log.Fatal("The environment variable OIDC_CLIENT_SECRET is not set")
	}

	callbackPort := os.Getenv("OIDC_CALLBACK_PORT")

	if callbackPort == "" {
		callbackPort = "6868"
	}

	metadata, err := Discover(provider)
	if err != nil {
		log.Fatal(err)
	}
	var authzEndpoint = metadata.AuthorizationEndpoint
	var tokenEndpoint = metadata.TokenEndpoint
  slog.Info(fmt.Sprintf("Authorization Endpoint : %s", authzEndpoint))
  slog.Info(fmt.Sprintf("Token Endpoint : %s", tokenEndpoint))

	go CallbackServer(clientId, clientSecret, tokenEndpoint, callbackPort, &wg)

	Authenticate(clientId, authzEndpoint, callbackPort)

	wg.Wait()

	fmt.Println("Done.")
}
