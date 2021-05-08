/*
[x] загрузить evn переменные:
    AUTH_SERVICE_URL = https://auth.loc
    CLIENT_ID =
    CLIENT_REDIRECT_URL =
    DISABLE_SSL_VERIFY = true
    go get github.com/joho/godotenv

[x] запустить HTTP server
  структура для запроса
  структура для ответа
  обработчик запроса (заполнение структуры)

[x] написать функцию логина

[x] проверить
- упаоквать в докер
- проверить в докере
- написать свагер или README
*/

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"

	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
)

type Config struct {
	AuthServiceUrl    string `env:"AUTH_SERVICE_URL,required"`
	ClientId          string `env:"CLIENT_ID,required"`
	ClientRedirectUrl string `env:"CLIENT_REDIRECT_URL,required"`
	DisableSSLVerify  bool   `env:"DISABLE_SSL_VERIFY"`
	ListenPort        int    `env:"PORT" envDefault:"80"`
}

type AppLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AppLoginResponse struct {
	AccessToken string `json:"access_token"`
}

type LoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

type ConsentResponse struct {
	LoginResponse
}

type ConsentRequest struct {
	Scopes    []string `json:"scopes"`
	Challenge string   `json:"challenge"`
	Remember  bool     `json:"remember"`
}

type CodeRequest struct {
	ClientId     string `json:"client_id"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	State        int    `json:"state"`
	GrantType    string `json:"grant_type"`
	RedirectUri  string `json:"redirect_uri"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type User struct {
	Email    string
	Password string
	Token    string
}

func LoadAppConfig() Config {
	cnf := Config{}
	if err := env.Parse(&cnf); err != nil {
		log.Fatalf("Failed to initialize app config: %+v\n", err)
	}

	if cnf.AuthServiceUrl == "" {
		log.Fatal("")
	}

	return cnf
}

var appConf Config

func init() {
	// Загружаем переменные окружения из .env файла
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	appConf = LoadAppConfig()

	if appConf.DisableSSLVerify {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	http.HandleFunc("/", loginAction)

	err := http.ListenAndServe(":"+strconv.Itoa(appConf.ListenPort), nil)
	if err != nil {
		log.Fatal(err)
	}
}

func loginAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		msg := "Only POST method allowed"
		http.Error(w, msg, http.StatusBadRequest)
		log.Println("ERR: " + msg)
		return
	}

	loginReqeust := AppLoginRequest{}
	bodyContent, err := ioutil.ReadAll(r.Body)
	if err != nil {
		msg := "Failed to read reqeust body: " + err.Error()
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println("ERR: " + msg)
		return
	}

	err = json.Unmarshal(bodyContent, &loginReqeust)
	if err != nil {
		msg := "Failed to decode request body: " + err.Error()
		http.Error(w, msg, http.StatusBadRequest)
		log.Println("ERR: " + msg)
		return
	}

	if loginReqeust.Email == "" {
		msg := "Email required"
		http.Error(w, msg, http.StatusBadRequest)
		log.Println("ERR: " + msg)
		return
	}

	if loginReqeust.Password == "" {
		msg := "Password required"
		http.Error(w, msg, http.StatusBadRequest)
		log.Println("ERR: " + msg)
		return
	}

	token, err := authorise(loginReqeust.Email, loginReqeust.Password)
	if err != nil {
		msg := "Authorisation failed: " + err.Error()
		http.Error(w, msg, 500)
		log.Println("ERR: " + msg)
		return
	}

	res := AppLoginResponse{
		AccessToken: token,
	}

	resJson, _ := json.Marshal(res)

	w.Header().Set("Content-Type", "application/json")
	w.Write(resJson)
}

func authorise(login, password string) (string, error) {
	clientID := appConf.ClientId
	redirectURL := appConf.ClientRedirectUrl
	baseUrl := appConf.AuthServiceUrl

	httpClient := createHttpClient()

	codeVerifier, _ := cv.CreateCodeVerifier()
	codeChallenge := codeVerifier.CodeChallengeS256()

	// construct the authorization URL (with Auth0 as the authorization provider)
	authorizationURL := fmt.Sprintf(
		"%s/oauth2/auth"+
			"?scope=offline"+
			"&response_type=code"+
			"&client_id=%s"+
			"&code_challenge=%s"+
			"&code_challenge_method=S256"+
			"&redirect_uri=%s"+
			"&state=1234567890"+
			"&scope=offline",
		baseUrl, clientID, url.QueryEscape(codeChallenge), url.QueryEscape(redirectURL))

	res, err := httpClient.Get(authorizationURL)
	if err != nil {
		return "", fmt.Errorf("Failed to get %s: %s", authorizationURL, err.Error())
	}

	challengeLogin := getLocationUrl(res).Query().Get("login_challenge")

	if challengeLogin == "" {
		return "", fmt.Errorf("Failed to get login_challenge from redirect")
	}

	// LOGIN
	loginUrl := baseUrl + "/api/v1/auth/login"
	loginData := map[string]string{
		"email":     login,
		"password":  password,
		"challenge": challengeLogin,
	}
	loginJson, _ := json.Marshal(loginData)

	res, err = httpClient.Post(loginUrl, "application/json", bytes.NewBuffer(loginJson))
	if err != nil {
		return "", fmt.Errorf("Failed to login with email & password: %s", err.Error())
	}

	loginResponse := new(LoginResponse)

	json.NewDecoder(res.Body).Decode(loginResponse)

	if loginResponse.RedirectTo == "" {
		return "", fmt.Errorf("Failed to login with email & password: no redirect_to parameter (access denied?)")
	}

	// Consent
	consentUrl := loginResponse.RedirectTo

	res, err = httpClient.Get(consentUrl)
	if err != nil {
		return "", fmt.Errorf("Faile to get consent page: %s", err.Error())
	}

	consentChallenge := getLocationUrl(res).Query().Get("consent_challenge")

	if consentChallenge == "" {
		return "", fmt.Errorf("Failed to get consent page: no consent_challenge parameter (hydra error?)")
	}

	// Consent API
	// consentRequest := &ConsentRequest{Challenge: consentChallenge, Remember: false}
	consentRequestJson := fmt.Sprintf("{\"scopes\":[\"offline\"],\"challenge\":\"%s\",\"remember\":false}", consentChallenge)

	consentApiUrl := baseUrl + "/api/v1/auth/consent"
	res, err = httpClient.Post(consentApiUrl, "application/json", bytes.NewBuffer([]byte(consentRequestJson)))
	if err != nil {
		return "", fmt.Errorf("Failed to confirm consents: %s", err.Error())
	}

	consentResponse := new(ConsentResponse)
	body, _ := ioutil.ReadAll(res.Body)
	json.Unmarshal(body, consentResponse)

	if consentResponse.RedirectTo == "" {
		return "", fmt.Errorf("Failed to confirm consents: server respond no redirect_to parameter")
	}

	finishUrl := consentResponse.RedirectTo

	res, err = httpClient.Get(finishUrl)
	if err != nil {
		return "", fmt.Errorf("Failed to finish authorisation process: %s", err.Error())
	}

	code := getLocationUrl(res).Query().Get("code")

	if code == "" {
		return "", fmt.Errorf("Failed to finish authorisation process: no `code` parameter")
	}

	// Access Token
	accessTokenRequest := url.Values{
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {codeVerifier.Value},
		"state":         {"1234567890"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURL},
	}

	accessTokenUrl := baseUrl + "/oauth2/token"

	res, err = httpClient.PostForm(accessTokenUrl, accessTokenRequest)
	if err != nil {
		return "", fmt.Errorf("Failed to change code to access_token: %s", err.Error())
	}

	body, _ = ioutil.ReadAll(res.Body)

	accessTokenResponse := new(TokenResponse)
	json.Unmarshal(body, accessTokenResponse)

	return accessTokenResponse.AccessToken, nil
}

func createHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
}

func getLocationUrl(res *http.Response) *url.URL {
	location := res.Header.Get("Location")
	locationUrl, _ := url.Parse(location)

	return locationUrl
}
