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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName   = "tekton_dashboard_session"
	oauthStateCookie    = "tekton_dashboard_oauth_state"
	defaultSessionHours = 12
)

type sessionPayload struct {
	Email     string `json:"email"`
	Subject   string `json:"sub"`
	ExpiresAt int64  `json:"exp"`
}

func (s *Service) setSession(w http.ResponseWriter, email, subject string) {
	payload := sessionPayload{
		Email:     email,
		Subject:   subject,
		ExpiresAt: time.Now().Add(defaultSessionHours * time.Hour).Unix(),
	}
	raw, _ := json.Marshal(payload)
	sig := sign(raw, s.cfg.CookieSecret)
	value := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   defaultSessionHours * 60 * 60,
	})
}

func (s *Service) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})
}

func (s *Service) sessionFromRequest(r *http.Request) (*sessionPayload, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, errors.New("no session")
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid session")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(sig, sign(raw, s.cfg.CookieSecret)) {
		return nil, errors.New("bad session signature")
	}
	var payload sessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if time.Now().Unix() > payload.ExpiresAt {
		return nil, errors.New("session expired")
	}
	return &payload, nil
}

func sign(raw []byte, secret string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(raw)
	return m.Sum(nil)
}

func emailAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return email != ""
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, allowed := range domains {
		if domain == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}
