package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const OIDCFlowContextKey = "oidc_oauth_flow"

// OIDCFlow holds the verifier and browser binding only on the server. Settings
// are pinned for the ten-minute flow, so a configuration change cannot mix issuers.
type OIDCFlow struct {
	CodeVerifier          string `json:"code_verifier"`
	Nonce                 string `json:"nonce"`
	BrowserBinding        string `json:"browser_binding"`
	ClientID              string `json:"client_id"`
	RedirectURI           string `json:"redirect_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	ConfigurationHash     string `json:"configuration_hash"`
}

func oidcConfigurationHash() string {
	settings := system_setting.GetOIDCSettings()
	encoded, _ := common.Marshal(settings)
	return common.GenerateHMACWithKey([]byte("oidc-config:"+common.SessionSecret), string(encoded)+system_setting.ServerAddress)
}

func NewOIDCFlow() (*OIDCFlow, error) {
	settings := system_setting.GetOIDCSettings()
	for _, endpoint := range []string{settings.WellKnown, settings.AuthorizationEndpoint, settings.TokenEndpoint, settings.UserInfoEndpoint, system_setting.ServerAddress} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, NewOAuthError(common.NewMessage(msgTokenFailed, map[string]any{"provider": "OIDC"}))
		}
	}
	if !settings.Enabled || settings.ClientId == "" || settings.ClientSecret == "" || !strings.HasSuffix(settings.WellKnown, "/.well-known/openid-configuration") {
		return nil, NewOAuthError(common.NewMessage(msgTokenFailed, map[string]any{"provider": "OIDC"}))
	}
	return &OIDCFlow{
		CodeVerifier: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(), BrowserBinding: oauth2.GenerateVerifier(),
		ClientID: settings.ClientId, RedirectURI: strings.TrimRight(system_setting.ServerAddress, "/") + "/oauth/oidc",
		AuthorizationEndpoint: settings.AuthorizationEndpoint, ConfigurationHash: oidcConfigurationHash(),
	}, nil
}

func (flow *OIDCFlow) AuthorizationURL(state string) string {
	endpoint, _ := url.Parse(flow.AuthorizationEndpoint)
	values := endpoint.Query()
	values.Set("client_id", flow.ClientID)
	values.Set("redirect_uri", flow.RedirectURI)
	values.Set("response_type", "code")
	values.Set("scope", "openid profile email")
	values.Set("state", state)
	values.Set("nonce", flow.Nonce)
	values.Set("code_challenge", oauth2.S256ChallengeFromVerifier(flow.CodeVerifier))
	values.Set("code_challenge_method", "S256")
	endpoint.RawQuery = values.Encode()
	return endpoint.String()
}

func oidcCookieName(state string) string {
	digest := sha256.Sum256([]byte(state))
	return "__Host-newapi_oidc_" + base64.RawURLEncoding.EncodeToString(digest[:12])
}

func (flow *OIDCFlow) SetBrowserCookie(c *gin.Context, state string, maxAge int) {
	value := flow.BrowserBinding
	if maxAge < 0 {
		value = ""
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: oidcCookieName(state), Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (flow *OIDCFlow) MatchesBrowser(c *gin.Context, state string) bool {
	value, err := c.Cookie(oidcCookieName(state))
	return err == nil && len(flow.BrowserBinding) >= 43 && subtle.ConstantTimeCompare([]byte(value), []byte(flow.BrowserBinding)) == 1
}

// OIDCProvider caches discovery and JWKS while configuration remains unchanged.
type OIDCProvider struct {
	client       *http.Client
	mutex        sync.Mutex
	discoveryURL string
	discovered   *oidc.Provider
}

func NewOIDCProvider(client *http.Client) *OIDCProvider { return &OIDCProvider{client: client} }

func init() { Register("oidc", NewOIDCProvider(&http.Client{Timeout: 20 * time.Second})) }

func (p *OIDCProvider) GetName() string {
	return system_setting.GetOIDCSettings().GetEffectiveDisplayName()
}
func (p *OIDCProvider) IsEnabled() bool { return system_setting.GetOIDCSettings().Enabled }

func (p *OIDCProvider) discovery(ctx context.Context, wellKnown string) (*oidc.Provider, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.discovered != nil && p.discoveryURL == wellKnown {
		return p.discovered, nil
	}
	issuer, ok := strings.CutSuffix(wellKnown, "/.well-known/openid-configuration")
	if !ok {
		return nil, fmt.Errorf("invalid discovery URL")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	p.discovered, p.discoveryURL = provider, wellKnown
	return provider, nil
}

func (p *OIDCProvider) ExchangeToken(ctx context.Context, code string, c *gin.Context) (*OAuthToken, error) {
	failure := NewOAuthError(common.NewMessage(msgInvalidCode))
	value, _ := c.Get(OIDCFlowContextKey)
	flow, ok := value.(*OIDCFlow)
	if !ok || flow == nil || code == "" || flow.CodeVerifier == "" || flow.Nonce == "" || flow.ConfigurationHash != oidcConfigurationHash() || !p.IsEnabled() {
		return nil, failure
	}
	client := p.client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, client)
	settings := system_setting.GetOIDCSettings()
	provider, err := p.discovery(ctx, settings.WellKnown)
	if err != nil {
		return nil, failure
	}
	var metadata struct {
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil || provider.Endpoint().AuthURL != settings.AuthorizationEndpoint || provider.Endpoint().TokenURL != settings.TokenEndpoint || metadata.UserInfoEndpoint != settings.UserInfoEndpoint {
		return nil, failure
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	config := oauth2.Config{ClientID: flow.ClientID, ClientSecret: settings.ClientSecret, RedirectURL: flow.RedirectURI, Endpoint: endpoint}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(flow.CodeVerifier))
	if err != nil || token.AccessToken == "" {
		return nil, failure
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, failure
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: flow.ClientID}).Verify(ctx, rawIDToken)
	if err != nil || verified.Subject == "" || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, failure
	}
	if verified.AccessTokenHash != "" {
		if err := verified.VerifyAccessToken(token.AccessToken); err != nil {
			return nil, failure
		}
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != verified.Subject || !info.EmailVerified || info.Email == "" {
		return nil, failure
	}
	var claims struct {
		Name     string `json:"name"`
		Username string `json:"preferred_username"`
	}
	if err := info.Claims(&claims); err != nil {
		return nil, failure
	}
	// OIDC subject IDs are unique only within their issuer. Keep that namespace
	// in the stored identity without depending on mutable email addresses.
	digest := sha256.Sum256([]byte(verified.Issuer + "\x00" + verified.Subject))
	user := &OAuthUser{ProviderUserID: "oidc:" + base64.RawURLEncoding.EncodeToString(digest[:]), Username: claims.Username, DisplayName: claims.Name, Email: info.Email}
	return &OAuthToken{AccessToken: token.AccessToken, TokenType: token.TokenType, IDToken: rawIDToken, ClientID: flow.ClientID, verifiedOIDCUser: user}, nil
}

func (p *OIDCProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	if token == nil || token.verifiedOIDCUser == nil {
		return nil, NewOAuthError(common.NewMessage(msgGetUserFailed))
	}
	return token.verifiedOIDCUser, nil
}

func (p *OIDCProvider) IsUserIDTaken(providerUserID string) bool {
	return model.IsOidcIdAlreadyTaken(providerUserID)
}

func (p *OIDCProvider) FillUserByProviderID(user *model.User, providerUserID string) error {
	user.OidcId = providerUserID
	return user.FillUserByOidcId()
}

func (p *OIDCProvider) SetProviderUserID(user *model.User, providerUserID string) {
	user.OidcId = providerUserID
}

func (p *OIDCProvider) GetProviderPrefix() string {
	return "oidc_"
}

// ProviderUserIDColumn returns the users-table column storing this provider's user ID.
func (p *OIDCProvider) ProviderUserIDColumn() string {
	return "oidc_id"
}
