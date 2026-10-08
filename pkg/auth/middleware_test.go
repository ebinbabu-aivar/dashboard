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

import "testing"

func TestBypassAuth(t *testing.T) {
	if !bypassAuth("/health") || !bypassAuth("/readiness") || !bypassAuth("/auth/login") {
		t.Fatal("expected health, readiness, and auth routes to bypass")
	}
	if bypassAuth("/v1/properties") {
		t.Fatal("expected API route to require auth when enabled")
	}
}

func TestEmailAllowedEmptyDomains(t *testing.T) {
	if !emailAllowed("user@example.com", nil) {
		t.Fatal("empty domain list should allow any email")
	}
}
