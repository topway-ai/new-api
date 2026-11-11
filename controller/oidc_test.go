package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type oidcTestGrant struct{ challenge, nonce string }
type oidcFixture struct {
	user       *model.User
	identity   service.AuthIdentity
	server     *httptest.Server
	key        *rsa.PrivateKey
	grants     map[string]oidcTestGrant
	fault      string
	tokenCalls int
}

func setupOIDCTest(t *testing.T) *oidcFixture {
	t.Helper()
	user, identity := setupSecurityEnrollmentTest(t)
	require.NoError(t, model.DB.AutoMigrate(&model.ExternalIdentityClaim{}))
	oldSettings := *system_setting.GetOIDCSettings()
	oldAddress, oldProvider := system_setting.ServerAddress, oauth.GetProvider("oidc")
	oldRegister := common.RegisterEnabled
	common.RegisterEnabled = false
	t.Cleanup(func() {
		*system_setting.GetOIDCSettings() = oldSettings
		system_setting.ServerAddress = oldAddress
		oauth.Register("oidc", oldProvider)
		common.RegisterEnabled = oldRegister
	})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &oidcFixture{user: user, identity: identity, key: key, grants: map[string]oidcTestGrant{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			result = map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "userinfo_endpoint": f.server.URL + "/userinfo", "jwks_uri": f.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}}
		case "/jwks":
			result = map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
		case "/token":
			f.tokenCalls++
			require.NoError(t, r.ParseForm())
			grant, ok := f.grants[r.Form.Get("code")]
			if !ok || r.Form.Get("client_id") != "new-api-web" || r.Form.Get("client_secret") != "test-secret" || r.Form.Get("redirect_uri") != "https://api.example.test/oauth/oidc" || r.Form.Get("grant_type") != "authorization_code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != grant.challenge {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"invalid_grant"}`)
				return
			}
			delete(f.grants, r.Form.Get("code"))
			claims := jwt.MapClaims{"iss": f.server.URL, "sub": "stable-subject", "aud": "new-api-web", "nonce": grant.nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
			signingKey := key
			switch f.fault {
			case "issuer":
				claims["iss"] = "https://wrong.example"
			case "audience":
				claims["aud"] = "other-client"
			case "nonce":
				claims["nonce"] = "wrong"
			case "expired-token":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "signature":
				signingKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test"
			signed, err := token.SignedString(signingKey)
			require.NoError(t, err)
			result = map[string]any{"access_token": "test-access", "id_token": signed, "token_type": "Bearer"}
		case "/userinfo":
			require.Equal(t, "Bearer test-access", r.Header.Get("Authorization"))
			subject := "stable-subject"
			if f.fault == "subject" {
				subject = "different-subject"
			}
			result = map[string]any{"sub": subject, "email": "user@example.test", "email_verified": f.fault != "unverified-email", "name": "Test User"}
		default:
			w.WriteHeader(404)
			return
		}
		data, err := common.Marshal(result)
		require.NoError(t, err)
		_, _ = w.Write(data)
	}))
	t.Cleanup(f.server.Close)
	*system_setting.GetOIDCSettings() = system_setting.OIDCSettings{Enabled: true, ClientId: "new-api-web", ClientSecret: "test-secret", WellKnown: f.server.URL + "/.well-known/openid-configuration", AuthorizationEndpoint: f.server.URL + "/authorize", TokenEndpoint: f.server.URL + "/token", UserInfoEndpoint: f.server.URL + "/userinfo"}
	system_setting.ServerAddress = "https://api.example.test"
	oauth.Register("oidc", oauth.NewOIDCProvider(f.server.Client()))
	digest := sha256.Sum256([]byte(f.server.URL + "\x00stable-subject"))
	require.NoError(t, model.DB.Model(user).Update("oidc_id", "oidc:"+base64.RawURLEncoding.EncodeToString(digest[:])).Error)
	require.NoError(t, model.InitializeExternalIdentityClaims())
	return f
}

func (f *oidcFixture) start(t *testing.T, intent string) (string, string, *http.Cookie) {
	t.Helper()
	identity := service.AuthIdentity{}
	proof := ""
	if intent == "bind" {
		identity = f.identity
		proof = issueSecurityEnrollmentProof(t, identity, service.VerificationOperation{Scope: service.VerificationScopeAccountBind, Context: []byte(`{"provider":"oidc"}`)}, service.VerificationMethodPassword)
	}
	response := securityEnrollmentRequest("POST", "/api/oauth/state", `{"provider":"oidc","intent":"`+intent+`"}`, proof, identity, GenerateOAuthCode)
	var body struct {
		Success bool `json:"success"`
		Data    struct {
			State string `json:"flow_token"`
			URL   string `json:"authorization_url"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
	require.True(t, body.Success, response.Body.String())
	u, err := url.Parse(body.Data.URL)
	require.NoError(t, err)
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	require.Len(t, u.Query().Get("code_challenge"), 43)
	require.Equal(t, "openid profile email", u.Query().Get("scope"))
	require.NotEmpty(t, u.Query().Get("nonce"))
	require.Empty(t, u.Query().Get("code_verifier"))
	require.NotContains(t, response.Body.String(), "test-secret")
	require.NotContains(t, response.Body.String(), "browser_binding")
	cookies := response.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
	require.Equal(t, "/", cookies[0].Path)
	require.Empty(t, cookies[0].Domain)
	code := "code-" + body.Data.State
	f.grants[code] = oidcTestGrant{challenge: u.Query().Get("code_challenge"), nonce: u.Query().Get("nonce")}
	return body.Data.State, code, cookies[0]
}

func oidcCallback(state, code string, cookie *http.Cookie, identity service.AuthIdentity) *httptest.ResponseRecorder {
	path := "/api/oauth/oidc?" + url.Values{"state": {state}, "code": {code}}.Encode()
	return securityEnrollmentRequest("GET", path, "", "", identity, func(c *gin.Context) {
		if cookie != nil {
			c.Request.AddCookie(cookie)
		}
		c.Params = gin.Params{{Key: "provider", Value: "oidc"}}
		HandleOAuth(c)
	})
}

func TestOIDCLoginPKCEAndReplay(t *testing.T) {
	f := setupOIDCTest(t)
	state, code, cookie := f.start(t, "login")
	response := oidcCallback(state, code, cookie, service.AuthIdentity{})
	var body struct {
		Success bool `json:"success"`
		Data    struct {
			User struct {
				ID int `json:"id"`
			} `json:"user"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
	require.True(t, body.Success, response.Body.String())
	require.Equal(t, f.user.Id, body.Data.User.ID)
	require.Equal(t, 1, f.tokenCalls)
	require.Equal(t, 403, oidcCallback(state, code, cookie, service.AuthIdentity{}).Code)
	require.Equal(t, 1, f.tokenCalls)
	var stored model.User
	require.NoError(t, model.DB.First(&stored, f.user.Id).Error)
	require.Equal(t, f.user.Password, stored.Password)
	require.Equal(t, f.user.Role, stored.Role)
}

func TestOIDCRejectsInvalidFlowBeforeTokenExchange(t *testing.T) {
	for _, fault := range []string{"missing-cookie", "wrong-cookie", "wrong-state", "expired-state", "wrong-provider", "changed-settings", "binding-session"} {
		t.Run(fault, func(t *testing.T) {
			f := setupOIDCTest(t)
			intent := "login"
			if fault == "binding-session" {
				intent = "bind"
			}
			state, code, cookie := f.start(t, intent)
			switch fault {
			case "missing-cookie":
				cookie = nil
			case "wrong-cookie":
				cookie.Value = "unrelated-browser"
			case "wrong-state":
				state = "unrelated-state"
			case "expired-state":
				require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("provider = ?", "oidc").Update("expires_at", time.Now().Add(-time.Hour)).Error)
			case "wrong-provider":
				require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("provider = ?", "oidc").Update("provider", "github").Error)
			case "changed-settings":
				system_setting.GetOIDCSettings().ClientId = "changed"
			}
			response := oidcCallback(state, code, cookie, service.AuthIdentity{})
			require.True(t, response.Code == 403 || strings.Contains(response.Body.String(), `"success":false`), response.Body.String())
			require.Equal(t, 0, f.tokenCalls)
		})
	}
}

func TestOIDCRejectsInvalidIdentityAndPKCE(t *testing.T) {
	for _, fault := range []string{"issuer", "audience", "nonce", "expired-token", "signature", "subject", "unverified-email", "pkce"} {
		t.Run(fault, func(t *testing.T) {
			f := setupOIDCTest(t)
			f.fault = fault
			state, code, cookie := f.start(t, "login")
			if fault == "pkce" {
				grant := f.grants[code]
				grant.challenge = "wrong-challenge"
				f.grants[code] = grant
			}
			response := oidcCallback(state, code, cookie, service.AuthIdentity{})
			require.Contains(t, response.Body.String(), `"success":false`)
			require.NotContains(t, response.Body.String(), "test-access")
			require.NotContains(t, response.Body.String(), "test-secret")
		})
	}
}
