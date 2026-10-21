package vertexai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func testEmbedAuth() *Auth {
	auth, err := NewAuth(context.Background(), func(context.Context) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), nil
	})
	if err != nil {
		panic(err)
	}
	return auth
}

func TestNewEmbedClientHasBoundedTransportTimeout(t *testing.T) {
	client, err := NewEmbedClient(testEmbedAuth(), EmbedConfig{Project: "proj-x", Location: "us-central1", Model: "model-x", Dimensions: 1, MaxTextBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	if client.httpC == nil || client.httpC.Timeout != defaultEmbedHTTPTimeout || client.httpC.Timeout <= 0 {
		t.Fatalf("embedding HTTP timeout=%v, want %v", client.httpC.Timeout, defaultEmbedHTTPTimeout)
	}
}

func TestEmbedRejectsOversizedProviderResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", maxEmbedResponseBytes+1)))
	}))
	defer server.Close()
	client := &EmbedClient{
		auth: testEmbedAuth(), httpC: server.Client(), target: server.URL,
		cfg: EmbedConfig{Dimensions: 1, MaxTextBytes: 128},
	}
	_, err := client.Embed(context.Background(), "value", TaskTypeRetrievalDocument)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("oversized response error=%v, want bounded-read refusal", err)
	}
}

func TestEmbedTransportCannotHangWithoutCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"predictions":[{"embeddings":{"values":[1]}}]}`))
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 20 * time.Millisecond
	client := &EmbedClient{
		auth: testEmbedAuth(), httpC: httpClient, target: server.URL,
		cfg: EmbedConfig{Dimensions: 1, MaxTextBytes: 128},
	}
	started := time.Now()
	_, err := client.Embed(context.Background(), "value", TaskTypeRetrievalDocument)
	if err == nil || !strings.Contains(err.Error(), "request") {
		t.Fatalf("timeout error=%v, want transport refusal", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("embedding request ignored bounded timeout: %v", elapsed)
	}
}

func TestFlashTransportAndResponseAreBounded(t *testing.T) {
	client, err := NewFlashClient(testEmbedAuth(), FlashConfig{Project: "proj-x", Location: "us-central1", Model: "model-x", MaxOutputTokens: 16})
	if err != nil {
		t.Fatal(err)
	}
	if client.httpC == nil || client.httpC.Timeout != defaultFlashHTTPTimeout || client.httpC.Timeout <= 0 {
		t.Fatalf("flash HTTP timeout=%v, want %v", client.httpC.Timeout, defaultFlashHTTPTimeout)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", maxFlashResponseBytes+1)))
	}))
	defer server.Close()
	client.httpC = server.Client()
	client.target = server.URL
	_, err = client.Generate(context.Background(), "value")
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("oversized flash response error=%v, want bounded-read refusal", err)
	}
}

func TestVertexClientsValidateResponsesAndAttachOnlyToTheirRequest(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		code int
		call func(*EmbedClient, *FlashClient) error
	}{
		{
			name: "embed dimensions", body: `{"predictions":[{"embeddings":{"values":[1]}}]}`, code: http.StatusOK,
			call: func(embed *EmbedClient, _ *FlashClient) error {
				_, err := embed.Embed(context.Background(), "long input", TaskTypeRetrievalQuery)
				return err
			},
		},
		{
			name: "embed malformed", body: `{`, code: http.StatusOK,
			call: func(embed *EmbedClient, _ *FlashClient) error {
				_, err := embed.Embed(context.Background(), "input", TaskTypeRetrievalQuery)
				return err
			},
		},
		{
			name: "embed provider error", body: `denied`, code: http.StatusForbidden,
			call: func(embed *EmbedClient, _ *FlashClient) error {
				_, err := embed.Embed(context.Background(), "input", TaskTypeRetrievalQuery)
				return err
			},
		},
		{
			name: "flash missing candidate", body: `{"candidates":[]}`, code: http.StatusOK,
			call: func(_ *EmbedClient, flash *FlashClient) error {
				_, err := flash.Generate(context.Background(), "prompt")
				return err
			},
		},
		{
			name: "flash malformed", body: `{`, code: http.StatusOK,
			call: func(_ *EmbedClient, flash *FlashClient) error {
				_, err := flash.Generate(context.Background(), "prompt")
				return err
			},
		},
		{
			name: "flash provider error", body: `denied`, code: http.StatusForbidden,
			call: func(_ *EmbedClient, flash *FlashClient) error {
				_, err := flash.Generate(context.Background(), "prompt")
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("Authorization = %q", got)
				}
				w.WriteHeader(tt.code)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			embed := &EmbedClient{auth: testEmbedAuth(), httpC: server.Client(), target: server.URL, cfg: EmbedConfig{Dimensions: 2, MaxTextBytes: 3}}
			flash := &FlashClient{auth: testEmbedAuth(), httpC: server.Client(), target: server.URL, cfg: FlashConfig{MaxOutputTokens: 1}}
			if err := tt.call(embed, flash); err == nil {
				t.Fatal("client accepted invalid provider response")
			}
		})
	}
}

func TestVertexClientsReturnSuccessfulParsedValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/embed" {
			_, _ = w.Write([]byte(`{"predictions":[{"embeddings":{"values":[1,2]}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"answer"}]}}]}`))
	}))
	defer server.Close()
	embed := &EmbedClient{auth: testEmbedAuth(), httpC: server.Client(), target: server.URL + "/embed", cfg: EmbedConfig{Dimensions: 2, MaxTextBytes: 3}}
	values, err := embed.Embed(context.Background(), "input", TaskTypeRetrievalDocument)
	if err != nil || len(values) != 2 || values[1] != 2 {
		t.Fatalf("Embed() = %v, %v", values, err)
	}
	flash := &FlashClient{auth: testEmbedAuth(), httpC: server.Client(), target: server.URL + "/flash", cfg: FlashConfig{MaxOutputTokens: 1}}
	answer, err := flash.Generate(context.Background(), "prompt")
	if err != nil || answer != "answer" {
		t.Fatalf("Generate() = %q, %v", answer, err)
	}
}
