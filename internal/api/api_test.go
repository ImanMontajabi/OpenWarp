package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterMacIdentity(t *testing.T) {
	var gotPath, gotUA, gotCV string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotUA, gotCV = r.URL.Path, r.Header.Get("User-Agent"), r.Header.Get("CF-Client-Version")
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"id":"r1","token":"t","type":"macOS","model":"Mac16,8","config":{"peers":[{"public_key":"k"}]}}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	reg, err := c.Register(context.Background(), "key", "macOS", "Mac16,8", "en_US")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/"+MacAPIVersion+"/reg" || gotUA != MacUserAgent || gotCV != MacClientVersion {
		t.Fatalf("mac identity not used: path=%s ua=%s cv=%s", gotPath, gotUA, gotCV)
	}
	if body["type"] != "macOS" || body["model"] != "Mac16,8" || reg.Type != "macOS" {
		t.Fatalf("body/response wrong: %v %+v", body, reg)
	}

	// Other platforms keep the default identity.
	if _, err := c.Register(context.Background(), "key", "Android", "PC", "en_US"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/"+DefaultVersion+"/reg" || gotUA != UserAgent || gotCV != ClientVersion {
		t.Fatalf("default identity changed: path=%s ua=%s cv=%s", gotPath, gotUA, gotCV)
	}
}

func TestRegisterUnusableResponseIsDeleted(t *testing.T) {
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
			return
		}
		w.Write([]byte(`{"id":"r1","token":"t","config":{"peers":[]}}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	if _, err := c.Register(context.Background(), "key", "macOS", "Mac16,8", "en_US"); err == nil {
		t.Fatal("expected an error for a response without peers")
	}
	if !deleted {
		t.Fatal("stray registration was not deleted")
	}
}

func TestRegisterEnvelopeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"id":"r2","token":"t","type":"macOS","config":{"peers":[{"public_key":"k"}]}},"success":true,"errors":[]}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	reg, err := c.Register(context.Background(), "key", "macOS", "Mac16,8", "en_US")
	if err != nil {
		t.Fatal(err)
	}
	if reg.ID != "r2" || reg.Type != "macOS" || len(reg.Config.Peers) != 1 {
		t.Fatalf("envelope not decoded: %+v", reg)
	}
}

func TestRegisterMissingIDReportsFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"something":1,"other":{}}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	_, err := c.Register(context.Background(), "key", "macOS", "Mac16,8", "en_US")
	if err == nil || !strings.Contains(err.Error(), "other, something") {
		t.Fatalf("want error listing response fields, got %v", err)
	}
}

func TestMacIdentityFallsBackToAndroidOn4xx(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/"+MacAPIVersion+"/") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte(`[{"id":"d1","type":"macOS","model":"Mac16,8","active":true}]`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL, c.Identity = srv.URL, MacIdentity
	d, err := c.Devices(context.Background(), "r1", "t")
	if err != nil || len(d) != 1 || d[0].Model != "Mac16,8" {
		t.Fatalf("fallback failed: %v %+v", err, d)
	}
	if len(paths) != 2 || paths[1] != "/"+DefaultVersion+"/reg/r1/account/devices" {
		t.Fatalf("unexpected request sequence: %v", paths)
	}
}

func TestEnvelopeUnwrapAndErrors(t *testing.T) {
	ok := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok {
			w.Write([]byte(`{"result":[{"id":"d1","type":"macOS","model":"Mac16,8"}],"success":true,"errors":[]}`))
			return
		}
		w.Write([]byte(`{"result":null,"success":false,"errors":[{"code":1,"message":"nope"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL, c.Identity = srv.URL, MacIdentity
	d, err := c.Devices(context.Background(), "r1", "t")
	if err != nil || len(d) != 1 || d[0].Type != "macOS" {
		t.Fatalf("envelope not unwrapped: %v %+v", err, d)
	}
	ok = false
	if _, err := c.Devices(context.Background(), "r1", "t"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("success:false envelope not reported: %v", err)
	}
}
