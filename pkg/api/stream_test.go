package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func newTestAPI(t *testing.T, handler http.HandlerFunc, client ...*http.Client) *HTTPAPI {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	h, err := NewHTTPAPI(server.URL, "test-key", client...)
	if err != nil {
		t.Fatalf("NewHTTPAPI(%q) = %v, want nil", server.URL, err)
	}
	return h
}

func TestJSONRequestsPreserveMethodsAndSetContentType(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method || r.URL.Path != "/api/v2/test" {
					t.Errorf("ReqJSON request = %s %s, want %s /api/v2/test", r.Method, r.URL.Path, method)
				}
				if r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("ReqJSON headers = %v, want Bearer authentication and JSON content type", r.Header)
				}
				w.WriteHeader(http.StatusCreated)
				if _, err := io.WriteString(w, `{"id":"result"}`); err != nil {
					t.Errorf("write JSON response = %v, want nil", err)
				}
			})
			var result struct{ ID string }
			_, err := h.ReqJSON(t.Context(), method, "/api/v2/test", map[string]string{"name": "sample"}, &result)
			if err != nil || result.ID != "result" {
				t.Errorf("ReqJSON(%s) = %+v, %v, want id=result and nil error", method, result, err)
			}
		})
	}
}

func TestStructuredAndLegacyErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		title  string
		match  error
	}{
		{name: "legacy forbidden", status: 403, body: `{"code":403,"error":"missing permission"}`, title: "missing permission", match: ErrApiKeyInvalid},
		{name: "fuego forbidden", status: 403, body: `{"status":403,"title":"missing feature"}`, title: "missing feature", match: ErrApiKeyInvalid},
		{name: "not found", status: 404, body: `{"status":404,"title":"file not found"}`, title: "file not found", match: ErrNotFound},
		{name: "rate limited", status: 429, body: `{"status":429,"title":"too many requests"}`, title: "too many requests", match: ErrRateLimited},
		{name: "too large", status: 413, body: `{"status":413,"title":"quota exceeded","detail":"remaining 2 bytes"}`, title: "quota exceeded"},
		{name: "empty not found", status: 404, title: "Not Found", match: ErrNotFound},
		{name: "null quota", status: 413, body: `null`, title: "Request Entity Too Large"},
		{name: "html error", status: 500, body: `<h1>failure</h1>`, title: "Internal Server Error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				if _, err := io.WriteString(w, test.body); err != nil {
					t.Errorf("write error response = %v, want nil", err)
				}
			})
			var dest map[string]any
			_, err := h.GetJSON(t.Context(), "/error", &dest)
			problem, ok := errors.AsType[*APIError](err)
			if !ok {
				t.Fatalf("GetJSON(%s) error = %T (%v), want *APIError", test.name, err, err)
			}
			if problem.Status != test.status || problem.Title != test.title {
				t.Errorf("GetJSON(%s) error = %+v, want status=%d title=%q", test.name, problem, test.status, test.title)
			}
			if test.match != nil && !errors.Is(err, test.match) {
				t.Errorf("errors.Is(GetJSON(%s), %v) = false, want true", test.name, test.match)
			}
			response, err := h.Do(t.Context(), http.MethodPost, "/error", strings.NewReader("binary"))
			if err != nil {
				t.Fatalf("Do(%s) = %v, want nil transport error", test.name, err)
			}
			err = DecodeResponse(response, &dest)
			problem, ok = errors.AsType[*APIError](err)
			if !ok || problem.Status != test.status {
				t.Errorf("DecodeResponse(%s) = %v, want *APIError with status %d", test.name, err, test.status)
			}
		})
	}
}

func TestNoRedirectIsPerRequest(t *testing.T) {
	var followed atomic.Int64
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		followed.Add(1)
		return nil
	}}
	h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/finish", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	}, client)
	response, err := h.Do(t.Context(), http.MethodGet, "/start", nil, ReqOptions{NoRedirect: true})
	if err != nil {
		t.Fatalf("Do(NoRedirect=true) = %v, want nil", err)
	}
	response.Body.Close()
	if response.StatusCode != 307 || followed.Load() != 0 {
		t.Errorf("Do(NoRedirect=true) status=%d followed=%d, want 307 and 0", response.StatusCode, followed.Load())
	}
	response, err = h.Do(t.Context(), http.MethodGet, "/start", nil)
	if err != nil {
		t.Fatalf("Do(default redirects) = %v, want nil", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || followed.Load() != 1 {
		t.Errorf("Do(default redirects) status=%d followed=%d, want 200 and 1", response.StatusCode, followed.Load())
	}
}

func TestGetStreamDoesNotSendCredentialsOrCookies(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("GetStream(%s) headers = %v, want no authorization or cookies", r.URL.Path, r.Header)
		}
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "redirect-cookie", Value: "secret"})
			http.Redirect(w, r, "/finish", http.StatusFound)
			return
		}
		if _, err := io.WriteString(w, "file bytes"); err != nil {
			t.Errorf("write download = %v, want nil", err)
		}
	}, &http.Client{Jar: jar})
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "sensitive"}})
	response, err := h.GetStream(t.Context(), h.BaseURL+"/start")
	if err != nil {
		t.Fatalf("GetStream(start) = %v, want nil", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "file bytes" {
		t.Errorf("GetStream(start) body=%q error=%v, want file bytes and nil", body, err)
	}
	if len(jar.Cookies(u)) != 1 {
		t.Errorf("configured cookie jar size after GetStream = %d, want 1", len(jar.Cookies(u)))
	}
}

func TestGetStreamRejectsUnsafeURLs(t *testing.T) {
	h, err := NewHTTPAPI("http://example.invalid", "key")
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{"/relative", "file:///etc/passwd", "ftp://example.invalid/file", "http://user:password@example.invalid/file"} {
		if response, err := h.GetStream(t.Context(), rawURL); err == nil {
			response.Body.Close()
			t.Errorf("GetStream(%q) error = nil, want invalid URL", rawURL)
		}
	}
}

func TestDoHonorsCanceledContext(t *testing.T) {
	h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled Do reached server") })
	h.rateLimiter = NewRateLimiter(1)
	h.rateLimiter.Allow()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := h.Do(ctx, http.MethodGet, "/test", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("Do(canceled context) = %v, want context.Canceled", err)
	}
}

func TestConcurrentRateLimitResponses(t *testing.T) {
	var requests atomic.Int64
	h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		limit := "80"
		if requests.Add(1)%2 == 0 {
			limit = "90"
		}
		w.Header().Set("x-ratelimit-limit", limit)
		w.WriteHeader(http.StatusTooManyRequests)
	})
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			response, err := h.Do(t.Context(), http.MethodGet, "/test", nil)
			if err != nil {
				t.Errorf("Do(concurrent) = %v, want nil transport error", err)
				return
			}
			response.Body.Close()
		})
	}
	wg.Wait()
}

func TestRateLimitRetryDelay(t *testing.T) {
	h := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ratelimit-retry-after", "1500ms")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := io.WriteString(w, `{"status":429,"title":"rate limited"}`); err != nil {
			t.Errorf("write rate-limit response = %v, want nil", err)
		}
	})
	var result map[string]any
	_, err := h.GetJSON(t.Context(), "/limited", &result)
	problem, ok := errors.AsType[*APIError](err)
	if !ok || problem.RetryAfter != 2 || !errors.Is(err, ErrRateLimited) {
		t.Errorf("GetJSON(limited) = %v, want typed rate-limit error with 2 second retry delay", err)
	}
}

type trackedResponseBody struct {
	io.Reader
	closed bool
}

func (b *trackedResponseBody) Close() error {
	b.closed = true
	return nil
}

func TestDecodeResponseClosesBodies(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusRequestEntityTooLarge} {
		body := &trackedResponseBody{Reader: strings.NewReader(`{"id":"file-id"}`)}
		var result map[string]any
		err := DecodeResponse(&http.Response{StatusCode: status, Body: body}, &result)
		if !body.closed {
			t.Errorf("DecodeResponse(status=%d) body closed=false, want true", status)
		}
		if (err != nil) != (status != http.StatusOK) {
			t.Errorf("DecodeResponse(status=%d) = %v, want error=%t", status, err, status != http.StatusOK)
		}
	}
}
