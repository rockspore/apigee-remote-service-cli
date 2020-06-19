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

package provision

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/apigee"
	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/jarcoal/httpmock"
)

const (
	mockOrg        = "org"
	mockEnv        = "env"
	mockUser       = "user"
	mockPassword   = "password"
	mockDevEmail   = "developer@mock.net"
	mockRuntime    = "mock.runtime.com"
	mockNameSapce  = "namespace"
	mockToken      = "token"
	mockManagement = "api.mock.apigee.com"

	legacyEdgeHost = "api.enterprise.apigee.com"
	legacyCredHost = "istioservices.apigee.net"

	hybridHost = "apigee.googleapis.com"

	internalProxyURL      = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/edgemicro-internal/deployments\z`
	internalProxyURLNoEnv = `=~^https://%s/v1/organizations/(\w+)/apis/edgemicro-internal\z`
	internalDeployURL     = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/edgemicro-internal/revisions/(\d+)/deployments\z`

	getDeployedURL      = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/remote-service/deployments\z`
	getDeployedURLNoEnv = `=~^https://%s/v1/organizations/(\w+)/apis/remote-service\z`
	deployURL           = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/remote-service/revisions/(\d+)/deployments\z`
	deployURLNoEnv      = `=~^https://%s/v1/organizations/(\w+)/apis\z`
	cachesURLNoEnv      = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/caches\z`
	credentialURL       = `=~^https://%s/edgemicro/credential/organization/(\w+)/environment/(\w+)\z`
	kvmURL              = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/keyvaluemaps\z`
	apiProductURL       = `=~^https://%s/v1/organizations/(\w+)/apiproducts\z`
	developerURL        = `=~^https://%s/v1/organizations/(\w+)/developers\z`
	appURL              = `=~^https://%s/v1/organizations/(\w+)/developers/%s/apps\z`

	legacyRemoteServiceURL = `=~^https://%s-%s.apigee.net/remote-service/(\w+)\z`
	hybridRemoteServiceURL = `=~^https://%s/remote-service/(\w+)\z`
)

var (
	appCred = appCredential{
		Key:    "key",
		Secret: "secret",
	}
)

func TestVerifyRemoteServiceProxyTLS(t *testing.T) {

	count := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		count++
	}))
	defer ts.Close()

	auth := &apigee.EdgeAuth{}

	// try without InsecureSkipVerify
	p := &provision{
		RootArgs: &shared.RootArgs{
			RuntimeBase:        ts.URL,
			Token:              "-",
			InsecureSkipVerify: false,
		},
		verifyOnly: true,
	}
	if err := p.Resolve(false, false); err != nil {
		t.Fatal(err)
	}
	if err := p.verifyRemoteServiceProxy(auth, shared.Printf); err == nil {
		t.Errorf("got nil error, want TLS failure")
	}

	// try with InsecureSkipVerify
	p.InsecureSkipVerify = true
	if err := p.Resolve(false, false); err != nil {
		t.Fatal(err)
	}

	if err := p.verifyRemoteServiceProxy(auth, shared.Printf); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if count != 4 {
		t.Errorf("got %d, want %d", count, 4)
	}
}

func TestProvisionLegacySaaS(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// TODO to check the payload for applicable requests
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURL, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURLNoEnv, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURLNoEnv, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(cachesURLNoEnv, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURL, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(credentialURL, legacyCredHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(kvmURL, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))

	httpmock.RegisterResponder("GET", fmt.Sprintf(legacyRemoteServiceURL, mockOrg, mockEnv),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(legacyRemoteServiceURL, mockOrg, mockEnv),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))

	print := testutil.Printer("TestProvisionLegacySaaS")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", mockOrg, "-e", mockEnv, "-u", mockUser, "-p", mockPassword, "--legacy"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

}

func TestProvisionGCP(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// TODO to check the payload for applicable requests
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURL, hybridHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURLNoEnv, hybridHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURLNoEnv, hybridHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(cachesURLNoEnv, hybridHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURL, hybridHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(apiProductURL, hybridHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(developerURL, hybridHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(appURL, hybridHost, mockDevEmail),
		httpmock.NewStringResponder(200,
			`{"credentials": [{"consumerKey":"fake-key","consumerSecret":"fake-secret"}]}`))
	httpmock.RegisterResponder("POST", fmt.Sprintf(kvmURL, hybridHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))

	httpmock.RegisterResponder("GET", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))

	print := testutil.Printer("TestProvisionHybrid")

	mockRuntimeURL := "https://" + mockRuntime

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", mockOrg, "-e", mockEnv,
		"-d", mockDevEmail, "-r", mockRuntimeURL, "-n", mockNameSapce, "-t", mockToken}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}
func TestProvisionOPDK(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// TODO to check the payload for applicable requests
	httpmock.RegisterResponder("GET", fmt.Sprintf(internalProxyURL, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(internalProxyURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(internalDeployURL, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))

	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURL, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(cachesURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURL, mockManagement),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(credentialURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(kvmURL, mockManagement),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))

	httpmock.RegisterResponder("GET", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))

	print := testutil.Printer("TestProvisionOPDK")

	mockManagementURL := "https://" + mockManagement
	mockRuntimeURL := "https://" + mockRuntime

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", mockOrg, "-e", mockEnv, "-u", mockUser, "-p", mockPassword, "-r", mockRuntimeURL, "-m", mockManagementURL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}

func TestCreateLegacyCredential(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		count++
	}))
	defer ts.Close()

	p := &provision{
		RootArgs: &shared.RootArgs{
			InternalProxyURL: ts.URL,
			Org:              "org",
			Env:              "env",
		},
	}
	p.ClientOpts = &apigee.EdgeClientOptions{
		MgmtURL:            ts.URL,
		Org:                p.Org,
		Env:                p.Env,
		InsecureSkipVerify: p.InsecureSkipVerify,
		Auth: &apigee.EdgeAuth{
			SkipAuth: true,
		},
	}
	var err error
	if p.Client, err = apigee.NewEdgeClient(p.ClientOpts); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if _, err := p.createLegacyCredential(shared.Printf); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("got %d, want %d", count, 1)
	}
}

func TestCreateGCPCredential(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//TODO this is a bit ugly; it may be better to have well-defined mock targets
		if count != 5 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"credentials": [{
			"consumerKey":"fake-key",
			"consumerSecret":"fake-secret"}
			]}`))
		} else {
			// the second time the client tries to create the app
			w.WriteHeader(http.StatusConflict)
		}
		count++
	}))
	defer ts.Close()

	p := &provision{
		RootArgs: &shared.RootArgs{
			InternalProxyURL: ts.URL,
			Org:              "org",
			Env:              "env",
		},
	}
	p.ClientOpts = &apigee.EdgeClientOptions{
		MgmtURL:            ts.URL,
		Org:                p.Org,
		Env:                p.Env,
		InsecureSkipVerify: p.InsecureSkipVerify,
		Auth: &apigee.EdgeAuth{
			SkipAuth: true,
		},
	}
	var err error
	if p.Client, err = apigee.NewEdgeClient(p.ClientOpts); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if _, err := p.createGCPCredential(shared.Printf); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// recreate
	if _, err := p.createGCPCredential(shared.Printf); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if count != 8 {
		t.Errorf("got %d, want %d", count, 8)
	}
}
