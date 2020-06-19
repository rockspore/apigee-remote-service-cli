// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/jarcoal/httpmock"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func TestTokenCreate(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := tokenResponse{
			Token: "/token/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	print := testutil.Printer("TestCreateToken")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "create", "--runtime", ts.URL, "--id", "/id/", "--secret", "/secret/"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"/token/"}

	print.Check(t, want)
}

func TestTokenInspect(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	key, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(key)
	}))
	defer ts.Close()

	print := testutil.Printer("TestInspectToken")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "inspect", "--runtime", ts.URL, "-v"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	token, err := generateJWT(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCmd.SetIn(strings.NewReader(token))

	if err = rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{`{
	"aud": [
		"remote-service-client"
	],
	"iss": "https://org-env.apigee.net/remote-service/token",
	"jti": "/id/",
	"access_token": "/token/",
	"api_product_list": [
		"/product/"
	],
	"application_name": "/appname/",
	"client_id": "/clientid/",
	"scope": "scope1 scope2"
}`,
		"\nverifying...",
		"valid token",
	}

	print.Check(t, want)
}

func TestTokenRotateCert(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://org-env.apigee.net/remote-service/certs",
		httpmock.NewStringResponder(200, `{"keys":[{"alg":"RS256","e":"AQAB","kid":"2020-01-01T00:00:00-00:00","kty":"RSA","n":"old-fake-key"}]}`))

	httpmock.RegisterResponder("POST", "https://org-env.apigee.net/remote-service/rotate",
		httpmock.NewStringResponder(200, ""))

	config := []byte(`tenant:
  internal_api: https://istioservices.apigee.net/edgemicro
  remote_service_api: https://org-env.apigee.net/remote-service
  org_name: org
  env_name: env
  key: fake-key
  secret: fake-secret`)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	print := testutil.Printer("TestTokenRotateCert")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "rotate-cert", "--config", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"certificate successfully rotated"}

	print.Check(t, want)
}

func TestTokenCreateSecret(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[{"alg":"RS256","e":"AQAB","kid":"2020-01-01T00:00:00-00:00","kty":"RSA","n":"fake-key"}]}`))
	}))
	defer ts.Close()

	print := testutil.Printer("TestTokenCreateSecret")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "create-secret", "--runtime", ts.URL, "-o", "org", "-e", "env"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"# Secret for apigee-remote-service-envoy",
		"# generated by apigee-remote-service-cli provision on",
		`apiVersion: v1
kind: Secret
metadata:
  name: org-env-policy-secret
  namespace: apigee
type: Opaque
data:`,
	}

	print.CheckPrefix(t, want)
}

func generateJWT(privateKey *rsa.PrivateKey) (string, error) {

	token := jwt.New()
	token.Set(jwt.AudienceKey, "remote-service-client")
	token.Set(jwt.JwtIDKey, "/id/")
	token.Set(jwt.IssuerKey, "https://org-env.apigee.net/remote-service/token")
	token.Set("access_token", "/token/")
	token.Set("client_id", "/clientid/")
	token.Set("application_name", "/appname/")
	token.Set("scope", "scope1 scope2")
	token.Set("api_product_list", []string{"/product/"})
	payload, err := token.Sign(jwa.RS256, privateKey)

	return string(payload), err
}
