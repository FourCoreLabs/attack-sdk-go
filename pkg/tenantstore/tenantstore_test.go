package tenantstore

import (
	"bytes"
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
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/tenantstore"
)

func tenantTestClient(t *testing.T, handler http.HandlerFunc, client ...*http.Client) *api.HTTPAPI {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	h, err := api.NewHTTPAPI(server.URL, "tenant-key", client...)
	if err != nil {
		t.Fatalf("NewHTTPAPI(%q) = %v, want nil", server.URL, err)
	}
	return h
}

func tenantJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := io.WriteString(w, body); err != nil {
		t.Errorf("write tenant response = %v, want nil", err)
	}
}

func TestMetadataListAndDelete(t *testing.T) {
	queries := make(chan url.Values, 1)
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tenant-key" {
			t.Errorf("tenant request authentication = %q, want Bearer tenant-key", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == TenantStoreV2URI+"/metadata":
			tenantJSON(t, w, 200, `{"soft_total_external_file_size":-1,"hard_total_external_file_size":5000,"current_total_external_file_size":1024}`)
		case r.Method == http.MethodGet && r.URL.Path == TenantStoreV2URI+"/files":
			queries <- r.URL.Query()
			tenantJSON(t, w, 200, `{"size":5,"offset":10,"total_rows":1,"data":[{"id":"file-id","attachment_type":"permanant_store","attachment_name":"sample.bin","object_path":"tenant://bucket/42/file-id","attachment_size":12,"relation_count":2,"metadata":{"sha256":"hash"}}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == TenantStoreV2URI+"/files/file-id":
			tenantJSON(t, w, 200, `{"success":true,"id":"file-id"}`)
		default:
			t.Errorf("tenant request = %s %s, want metadata/list/delete route", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	})
	metadata, err := GetMetadata(t.Context(), h)
	if err != nil || metadata.SoftTotalExternalFileSize != -1 || metadata.CurrentTotalExternalFileSize != 1024 {
		t.Errorf("GetMetadata = %+v, %v, want unlimited soft quota and 1024 usage", metadata, err)
	}
	listed, err := ListFiles(t.Context(), h, ListFilesOpts{
		Size: 5, Offset: 10, Order: "-updated_at", Name: "sample",
		MimeType: []string{"text/plain", "application/octet-stream"}, AttachmentName: []string{"sample.bin", "other.bin"},
		Type: []model.FileType{model.Temporary, model.PermanentStore}, StartFileSize: new(uint64(0)), EndFileSize: new(uint64(1024)),
	})
	if err != nil {
		t.Fatalf("ListFiles = %v, want nil", err)
	}
	query := <-queries
	if listed.TotalRows != 1 || len(listed.Data) != 1 || listed.Data[0].Type != model.PermanentStore || listed.Data[0].ObjectPath != "tenant://bucket/42/file-id" || listed.Data[0].RelationCount != 2 {
		t.Errorf("ListFiles = %+v, want typed tenant file and pagination", listed)
	}
	for key, want := range map[string]string{"size": "5", "offset": "10", "order": "-updated_at", "filter[name]": "sample", "filter[mime_type]": "text/plain,application/octet-stream", "filter[attachment_name]": "sample.bin,other.bin", "filter[type]": "temporary,permanant_store", "filter[start_file_size]": "0", "filter[end_file_size]": "1024"} {
		if query.Get(key) != want {
			t.Errorf("ListFiles query[%q] = %q, want %q", key, query.Get(key), want)
		}
	}
	deleted, err := DeleteFile(t.Context(), h, "file-id")
	if err != nil || !deleted.Success || deleted.ID != "file-id" {
		t.Errorf("DeleteFile = %+v, %v, want success and file-id", deleted, err)
	}
	_, err = ListFiles(t.Context(), h, ListFilesOpts{})
	if err != nil {
		t.Fatalf("ListFiles(defaults) = %v, want nil", err)
	}
	query = <-queries
	if query.Has("size") || query.Has("offset") || query.Has("filter[start_file_size]") {
		t.Errorf("ListFiles(defaults) query = %v, want omitted optional values", query)
	}
}

func TestUploadFileSendsRawBytes(t *testing.T) {
	payload := []byte{0, 1, 2, '\n', 255, '{', '}'}
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != TenantStoreV2URI+"/upload_file" {
			t.Errorf("UploadFile request = %s %s, want POST upload_file", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" || r.ContentLength != int64(len(payload)) {
			t.Errorf("UploadFile headers = %v length=%d, want binary content and length=%d", r.Header, r.ContentLength, len(payload))
		}
		if r.URL.Query().Get("size") != "7" || r.URL.Query().Get("attachment_name") != "sample & notes.bin" {
			t.Errorf("UploadFile query = %v, want encoded size and attachment name", r.URL.Query())
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, payload) {
			t.Errorf("UploadFile body = %v, %v, want %v", body, err, payload)
		}
		tenantJSON(t, w, 200, `{"id":"file-id","attachment_type":"temporary","object_path":"tenant://bucket/42/file-id","attachment_size":7,"mime_type":"application/octet-stream"}`)
	})
	file, err := UploadFile(t.Context(), h, bytes.NewReader(payload), UploadFileOpts{Size: int64(len(payload)), AttachmentName: "sample & notes.bin"})
	if err != nil || file.ID != "file-id" || file.Type != model.Temporary || file.ObjectPath != "tenant://bucket/42/file-id" || file.AttachmentSize != 7 {
		t.Errorf("UploadFile = %+v, %v, want complete temporary file", file, err)
	}
}

func TestUploadFileErrorsAreNotRetried(t *testing.T) {
	var requests atomic.Int64
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		tenantJSON(t, w, 413, `{"status":413,"title":"storage quota exceeded"}`)
	})
	_, err := UploadFile(t.Context(), h, strings.NewReader("bytes"), UploadFileOpts{Size: 5})
	problem, ok := errors.AsType[*api.APIError](err)
	if !ok || problem.Status != 413 || requests.Load() != 1 {
		t.Errorf("UploadFile(quota) = %v, requests=%d, want status=413 and one request", err, requests.Load())
	}
}

func TestUploadFileDoesNotReplayRedirects(t *testing.T) {
	var replayed atomic.Int64
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == TenantStoreV2URI+"/upload_file" {
			http.Redirect(w, r, "/replayed", http.StatusFound)
			return
		}
		replayed.Add(1)
	})
	_, err := UploadFile(t.Context(), h, strings.NewReader("bytes"), UploadFileOpts{Size: 5})
	problem, ok := errors.AsType[*api.APIError](err)
	if !ok || problem.Status != http.StatusFound || replayed.Load() != 0 {
		t.Errorf("UploadFile(redirect) = %v, replayed=%d, want redirect error and no replay", err, replayed.Load())
	}
}

func TestDownloadURLDoesNotFollowRedirect(t *testing.T) {
	var fetched atomic.Int64
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == TenantStoreV2URI+"/files/file-id/download" {
			http.Redirect(w, r, "http://"+r.Host+"/object?signature=a%2Fb&token=1", 307)
			return
		}
		fetched.Add(1)
	})
	location, err := GetDownloadURL(t.Context(), h, "file-id")
	if err != nil {
		t.Fatalf("GetDownloadURL = %v, want nil", err)
	}
	if location.RawQuery != "signature=a%2Fb&token=1" || fetched.Load() != 0 {
		t.Errorf("GetDownloadURL = %v fetched=%d, want preserved signature and no fetch", location, fetched.Load())
	}
}

func TestDownloadFileStreamsWithoutCredentials(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, TenantStoreV2URI) {
			if r.Header.Get("Authorization") != "Bearer tenant-key" {
				t.Errorf("download API authorization = %q, want API key", r.Header.Get("Authorization"))
			}
			http.Redirect(w, r, "http://"+r.Host+"/object", 307)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("presigned download headers = %v, want no credentials", r.Header)
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-release
		if _, err := io.WriteString(w, "streamed bytes"); err != nil {
			t.Errorf("write streamed body = %v, want nil", err)
		}
	}, &http.Client{Jar: jar})
	t.Cleanup(unblock)
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "sensitive"}})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	body, err := DownloadFile(ctx, h, "file-id")
	if err != nil {
		t.Fatalf("DownloadFile before body is available = %v, want stream without buffering", err)
	}
	defer body.Close()
	unblock()
	data, err := io.ReadAll(body)
	if err != nil || string(data) != "streamed bytes" {
		t.Errorf("DownloadFile body = %q, %v, want streamed bytes and nil", data, err)
	}
}

func TestDownloadErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		location string
		body     string
	}{
		{name: "missing file", status: 404, body: `{"status":404,"title":"file not found"}`},
		{name: "missing location", status: 307},
		{name: "unsafe scheme", status: 307, location: "file:///etc/passwd"},
		{name: "URL credentials", status: 307, location: "http://user:pass@example.test/file"},
		{name: "unexpected success", status: 200, body: `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if test.location != "" {
					w.Header().Set("Location", test.location)
				}
				tenantJSON(t, w, test.status, test.body)
			})
			if location, err := GetDownloadURL(t.Context(), h, "file-id"); err == nil {
				t.Errorf("GetDownloadURL(%s) = %v, nil, want error", test.name, location)
			}
		})
	}
}

func TestTenantStoreValidatesInputs(t *testing.T) {
	var requests atomic.Int64
	h := tenantTestClient(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) })
	for _, size := range []int64{0, -1} {
		if _, err := UploadFile(t.Context(), h, strings.NewReader("data"), UploadFileOpts{Size: size}); err == nil {
			t.Errorf("UploadFile(size=%d) error=nil, want validation error", size)
		}
	}
	if _, err := UploadFile(t.Context(), h, nil, UploadFileOpts{Size: 1}); err == nil {
		t.Error("UploadFile(nil reader) error=nil, want validation error")
	}
	for _, id := range []string{"", "..", "../other", "a/b", "a?query"} {
		if _, err := DeleteFile(t.Context(), h, id); err == nil {
			t.Errorf("DeleteFile(id=%q) error=nil, want validation error", id)
		}
		if _, err := GetDownloadURL(t.Context(), h, id); err == nil {
			t.Errorf("GetDownloadURL(id=%q) error=nil, want validation error", id)
		}
	}
	if _, err := ListFiles(t.Context(), h, ListFilesOpts{Size: -1}); err == nil {
		t.Error("ListFiles(size=-1) error=nil, want validation error")
	}
	if requests.Load() != 0 {
		t.Errorf("invalid tenant input HTTP requests = %d, want 0", requests.Load())
	}
}
