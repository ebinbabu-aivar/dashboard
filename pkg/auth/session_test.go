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

func TestEmailAllowedWithDomains(t *testing.T) {
	domains := []string{"example.com", "example.org"}
	if !emailAllowed("user@example.com", domains) {
		t.Fatal("expected example.com allowed")
	}
	if emailAllowed("user@gmail.com", domains) {
		t.Fatal("expected gmail blocked")
	}
}
