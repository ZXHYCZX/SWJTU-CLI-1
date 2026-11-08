package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"swjtu-cli/internal/config"
)

func TestAppClientDoSendsHeadersAndParsesData(t *testing.T) {
	var gotPath, gotUA, gotFromEAI, gotAuth, gotContent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUA = r.Header.Get("User-Agent")
		gotFromEAI = r.Header.Get("from-eai")
		gotAuth = r.Header.Get("authorization-str")
		_ = r.ParseForm()
		gotContent = r.PostForm.Get("content")
		_, _ = w.Write([]byte(`{"e":0,"m":"ok","d":{"week":7}}`))
	}))
	defer srv.Close()

	c := &AppClient{
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
		Session: &config.AppSession{AccessToken: "test-token"},
	}
	data, err := c.Do(context.Background(), "/swjtu/frontend/term/app?current_time=1", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Week int `json:"week"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.Week != 7 {
		t.Fatalf("week = %d", v.Week)
	}
	if gotPath != "/swjtu/frontend/term/app" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.HasPrefix(gotUA, "ZhilinEai ZhilinSwjtuApp/") {
		t.Fatalf("User-Agent = %q", gotUA)
	}
	if gotFromEAI != "1" {
		t.Fatalf("from-eai = %q", gotFromEAI)
	}
	if gotContent == "" {
		t.Fatal("content form field is empty")
	}
	if gotAuth == "" {
		t.Fatal("authorization-str header is empty")
	}
}
