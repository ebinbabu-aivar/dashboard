/*
Copyright 2026 The Tekton Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the License governing permissions and
limitations under the License.
*/

package auth

import (
	"flag"
	"os"
	"strings"
)

// Config holds optional OIDC authentication settings.
type Config struct {
	Enabled      bool
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	CookieSecret string
	EmailDomains []string
	BaseURL      string
}

var (
	authEnabled      = flag.Bool("auth-enabled", false, "Require OIDC login before using the dashboard")
	authIssuerURL    = flag.String("auth-oidc-issuer-url", "", "OIDC issuer URL")
	authClientID     = flag.String("auth-oidc-client-id", "", "OIDC client ID (overridden by AUTH_OIDC_CLIENT_ID env)")
	authClientSecret = flag.String("auth-oidc-client-secret", "", "OIDC client secret (overridden by AUTH_OIDC_CLIENT_SECRET env)")
	authRedirectURL  = flag.String("auth-redirect-url", "", "OAuth redirect URL registered on the OIDC client")
	authCookieSecret = flag.String("auth-cookie-secret", "", "Session cookie HMAC secret (overridden by AUTH_COOKIE_SECRET env)")
	authEmailDomains = flag.String("auth-email-domains", "", "Optional comma-separated allowed email domains; empty allows any verified email")
	authBaseURL      = flag.String("auth-base-url", "", "External dashboard base URL used for logout redirect (no trailing slash)")
)

// LoadConfig builds Config from flags and environment (call after flag.Parse).
func LoadConfig() *Config {
	cfg := &Config{
		Enabled:      *authEnabled,
		IssuerURL:    strings.TrimSpace(*authIssuerURL),
		ClientID:     firstNonEmpty(os.Getenv("AUTH_OIDC_CLIENT_ID"), strings.TrimSpace(*authClientID)),
		ClientSecret: firstNonEmpty(os.Getenv("AUTH_OIDC_CLIENT_SECRET"), strings.TrimSpace(*authClientSecret)),
		RedirectURL:  strings.TrimSpace(*authRedirectURL),
		CookieSecret: firstNonEmpty(os.Getenv("AUTH_COOKIE_SECRET"), strings.TrimSpace(*authCookieSecret)),
		BaseURL:      strings.TrimRight(strings.TrimSpace(*authBaseURL), "/"),
	}
	for _, d := range strings.Split(*authEmailDomains, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			cfg.EmailDomains = append(cfg.EmailDomains, d)
		}
	}
	return cfg
}

func (c *Config) Valid() bool {
	if !c.Enabled {
		return true
	}
	return c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != "" &&
		c.RedirectURL != "" && c.CookieSecret != ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
