package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// providerDef holds an IdP's OAuth endpoints + how to read the user's email.
type providerDef struct {
	authURL  string
	tokenURL string
	scope    string
	fetchEmail func(ctx context.Context, hc *http.Client, accessToken string) (string, error)
}

var providers = map[string]providerDef{
	"google": {
		authURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		tokenURL: "https://oauth2.googleapis.com/token",
		scope:    "openid email",
		fetchEmail: func(ctx context.Context, hc *http.Client, tok string) (string, error) {
			var u struct {
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
			}
			if err := getJSON(ctx, hc, "https://openidconnect.googleapis.com/v1/userinfo", tok, &u); err != nil {
				return "", err
			}
			if u.Email == "" {
				return "", errors.New("oauth: google userinfo returned no email")
			}
			return u.Email, nil
		},
	},
	"github": {
		authURL:  "https://github.com/login/oauth/authorize",
		tokenURL: "https://github.com/login/oauth/access_token",
		scope:    "read:user user:email",
		fetchEmail: func(ctx context.Context, hc *http.Client, tok string) (string, error) {
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if err := getJSON(ctx, hc, "https://api.github.com/user/emails", tok, &emails); err != nil {
				return "", err
			}
			for _, e := range emails {
				if e.Primary && e.Verified {
					return e.Email, nil
				}
			}
			for _, e := range emails {
				if e.Verified {
					return e.Email, nil
				}
			}
			return "", errors.New("oauth: no verified github email")
		},
	},
}

// SupportedProvider reports whether the named provider is implemented (used by
// bff-console validation via the exported wrapper below).
func SupportedProvider(name string) bool {
	_, ok := providers[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// authRedirectURL builds the IdP authorize URL the visitor is bounced to.
func (c *Config) authRedirectURL(redirectURI, state string) string {
	pd := providers[c.provider]
	q := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {pd.scope},
		"state":         {state},
	}
	return pd.authURL + "?" + q.Encode()
}

// exchangeCode swaps an authorization code for an access token.
func (c *Config) exchangeCode(ctx context.Context, hc *http.Client, code, redirectURI string) (string, error) {
	pd := providers[c.provider]
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pd.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", errors.New("oauth: token exchange HTTP " + resp.Status)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", errors.New("oauth: token exchange returned no access_token")
	}
	return tr.AccessToken, nil
}

// getJSON performs an authorized GET and decodes a JSON body.
func getJSON(ctx context.Context, hc *http.Client, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return errors.New("oauth: userinfo HTTP " + resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
