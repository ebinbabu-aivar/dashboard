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
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tektoncd/dashboard/pkg/logging"
	"golang.org/x/oauth2"
)

// Service implements OIDC login, callback, logout, and session middleware.
type Service struct {
	cfg  *Config
	once sync.Once
	err  error
	prov *oidc.Provider
	oauth2.Config
}

func New(cfg *Config) *Service {
	return &Service{cfg: cfg}
}

func (s *Service) init(ctx context.Context) error {
	s.once.Do(func() {
		s.prov, s.err = oidc.NewProvider(ctx, s.cfg.IssuerURL)
		if s.err != nil {
			return
		}
		s.oauth2.Config = oauth2.Config{
			ClientID:     s.cfg.ClientID,
			ClientSecret: s.cfg.ClientSecret,
			RedirectURL:  s.cfg.RedirectURL,
			Endpoint:     s.prov.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		}
	})
	return s.err
}

// RegisterRoutes mounts /auth/* handlers on the dashboard mux.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/callback", s.handleCallback)
	mux.HandleFunc("/auth/logout", s.handleLogout)
}

// Middleware requires a valid session for all routes except bypass paths.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if bypassAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := s.sessionFromRequest(r); err != nil {
			if isAPIRequest(r) {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/auth/login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bypassAuth(path string) bool {
	switch {
	case path == "/health", path == "/readiness":
		return true
	case strings.HasPrefix(path, "/auth/"):
		return true
	default:
		return false
	}
}

func isAPIRequest(r *http.Request) bool {
	p := r.URL.Path
	return strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/apis/") || strings.HasPrefix(p, "/v1/")
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.init(r.Context()); err != nil {
		logging.Log.Errorf("auth init: %v", err)
		http.Error(w, "auth unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "auth error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL := s.oauth2.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	if err := s.init(r.Context()); err != nil {
		http.Error(w, "auth unavailable", http.StatusServiceUnavailable)
		return
	}
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil || stateCookie.Value == "" || r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, err := s.oauth2.Exchange(ctx, code)
	if err != nil {
		logging.Log.Errorf("oauth exchange: %v", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		http.Error(w, "missing id_token", http.StatusUnauthorized)
		return
	}
	verifier := s.prov.Verifier(&oidc.Config{ClientID: s.cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}
	if !emailAllowed(claims.Email, s.cfg.EmailDomains) {
		http.Error(w, "email not permitted", http.StatusForbidden)
		return
	}
	s.setSession(w, claims.Email, claims.Sub)
	rd := r.URL.Query().Get("rd")
	if rd == "" || !strings.HasPrefix(rd, "/") {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	target := s.cfg.BaseURL
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// LogoutPath returns the in-app logout URL for dashboard properties.
func (s *Service) LogoutPath() string {
	if !s.cfg.Enabled {
		return ""
	}
	return "/auth/logout"
}

// Enabled reports whether OIDC gate is active.
func (s *Service) Enabled() bool {
	return s.cfg.Enabled
}

// LoginPath is exposed to the UI via /v1/properties.
func (s *Service) LoginPath() string {
	if !s.cfg.Enabled {
		return ""
	}
	return "/auth/login"
}

// Describe returns a short config summary for logs (no secrets).
func (s *Service) Describe() string {
	if !s.cfg.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("oidc issuer=%s redirect=%s", s.cfg.IssuerURL, s.cfg.RedirectURL)
}
