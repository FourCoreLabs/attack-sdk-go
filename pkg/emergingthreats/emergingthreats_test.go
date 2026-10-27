package emergingthreats

import (
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
)

func campaignTestClient(t *testing.T, handler http.HandlerFunc) *api.HTTPAPI {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	h, err := api.NewHTTPAPI(server.URL, "campaign-key")
	if err != nil {
		t.Fatalf("NewHTTPAPI(%q) = %v, want nil", server.URL, err)
	}
	return h
}

func campaignJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := io.WriteString(w, body); err != nil {
		t.Errorf("write campaign response = %v, want nil", err)
	}
}

func TestCreateAndUpdateCampaign(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				wantPath := CampaignsV2URI
				if method == http.MethodPut {
					wantPath += "/campaign-id"
				}
				if r.Method != method || r.URL.Path != wantPath || r.Header.Get("Authorization") != "Bearer campaign-key" {
					t.Errorf("campaign write = %s %s headers=%v, want %s %s with API key", r.Method, r.URL.Path, r.Header, method, wantPath)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				var request struct {
					Name       string   `json:"name"`
					References []string `json:"references"`
					Entries    []struct {
						PayloadType string `json:"payload_type"`
						Payload     struct {
							Object string `json:"object"`
						} `json:"payload"`
					} `json:"emerging_threats"`
					DeleteFiles *bool `json:"delete_tenant_file_on_no_relation"`
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Errorf("decode campaign request = %v, want nil", err)
					w.WriteHeader(400)
					return
				}
				if request.Name != "IOC campaign" || len(request.References) != 1 || len(request.Entries) != 1 {
					t.Errorf("campaign write document = %+v, want campaign, references, and one entry", request)
				} else if request.Entries[0].PayloadType != "object" || request.Entries[0].Payload.Object != "tenant://bucket/org/file-id" {
					t.Errorf("campaign object entry = %+v, want object and tenant URI", request.Entries[0])
				}
				if method == http.MethodPut && (request.DeleteFiles == nil || *request.DeleteFiles) {
					t.Errorf("update cleanup flag = %v, want explicit false", request.DeleteFiles)
				}
				status := http.StatusOK
				if method == http.MethodPost {
					status = http.StatusCreated
				}
				campaignJSON(t, w, status, `{"id":"campaign-id","name":"IOC campaign","reference":["https://example.test/report"],"emerging_threats":[{"id":"entry-id","text":"entry description","type":"object","payload":{"object":"tenant://bucket/org/file-id"}}],"behaviour_analytics":{"email_attachment":{"total":3,"detected":2}},"total_hosts":1,"total_malware":2}`)
			})
			request := model.CampaignCreateRequest{
				Name: "IOC campaign", References: []string{"https://example.test/report"},
				EmergingThreats: []model.AttackInput{{Name: "sample", PayloadType: model.PayloadTypeObject, Payload: model.Payload{Object: "tenant://bucket/org/file-id"}}},
			}
			var result model.Campaign
			var err error
			if method == http.MethodPost {
				result, err = CreateCampaign(t.Context(), h, request)
			} else {
				result, err = UpdateCampaign(t.Context(), h, "campaign-id", model.CampaignUpdateRequest{CampaignCreateRequest: request, DeleteTenantFileOnNoRelation: false})
			}
			if err != nil {
				t.Fatalf("campaign write(%s) = %v, want nil", method, err)
			}
			if result.ID != "campaign-id" || len(result.Reference) != 1 || result.TotalHosts != 1 || result.TotalMalware != 2 || result.BehaviourAnalytics.EmailAttachment.Detected != 2 {
				t.Errorf("campaign write(%s) result = %+v, want complete campaign response", method, result)
			}
			if len(result.EmergingThreats) != 1 || result.EmergingThreats[0].Description != "entry description" {
				t.Errorf("campaign write(%s) entries = %+v, want description decoded from text", method, result.EmergingThreats)
			}
		})
	}
}

func TestDeleteCampaignOptionalCleanup(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(strconv.FormatBool(explicit), func(t *testing.T) {
			h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != CampaignsV2URI+"/campaign-id" {
					t.Errorf("DeleteCampaign request = %s %s, want DELETE campaign-id", r.Method, r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				if explicit {
					var request struct {
						DeleteFiles *bool `json:"delete_tenant_file_on_no_relation"`
					}
					if err := json.Unmarshal(body, &request); err != nil || request.DeleteFiles == nil || *request.DeleteFiles {
						t.Errorf("DeleteCampaign body = %q, %v, want explicit false cleanup", body, err)
					}
				} else if len(body) != 0 {
					t.Errorf("DeleteCampaign(nil) body = %q, want no body", body)
				}
				campaignJSON(t, w, 200, `{"success":true,"id":"campaign-id"}`)
			})
			var request *model.CampaignDeleteRequest
			if explicit {
				request = &model.CampaignDeleteRequest{DeleteTenantFileOnNoRelation: new(false)}
			}
			result, err := DeleteCampaign(t.Context(), h, "campaign-id", request)
			if err != nil || !result.Success || result.ID != "campaign-id" {
				t.Errorf("DeleteCampaign(explicit=%t) = %+v, %v, want successful campaign-id", explicit, result, err)
			}
		})
	}
}

func TestListGetAndFilterCampaignQueries(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 7)
	queries := make(chan url.Values, 1)
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.Query()
		if r.Method != http.MethodGet {
			t.Errorf("campaign read method = %s, want GET", r.Method)
		}
		switch r.URL.Path {
		case CampaignsV2URI:
			campaignJSON(t, w, 200, `{"size":10,"offset":20,"total_rows":1,"data":[{"id":"campaign-id"}]}`)
		case CampaignsV2URI + "/campaign-id":
			campaignJSON(t, w, 200, `{"id":"campaign-id"}`)
		case CampaignsV2URI + "/filters":
			campaignJSON(t, w, 200, `{"family":[{"count":2,"data":"sample"}]}`)
		default:
			t.Errorf("campaign read path = %s, want campaign route", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	filter := CampaignFilter{Family: []string{"first", "second"}, Region: []string{"country:IN"}, StartReleaseDate: start, EndReleaseDate: end}
	analytics := AnalyticsOpts{StartDayRange: start, EndDayRange: end, UseLink: new(false), UseAttachment: new(true), ExecutionType: []string{"firewall", "email_infiltration"}}
	listed, err := ListCampaigns(t.Context(), h, ListCampaignsOpts{CampaignFilter: filter, AnalyticsOpts: analytics, Size: 10, Offset: 20, Order: "-updated_at,name"})
	if err != nil || listed.TotalRows != 1 || len(listed.Data) != 1 {
		t.Fatalf("ListCampaigns = %+v, %v, want one campaign", listed, err)
	}
	query := <-queries
	for key, want := range map[string]string{"size": "10", "offset": "20", "order": "-updated_at,name", "filter[family]": "first,second", "filter[region]": "country:IN", "filter[use_link]": "false", "filter[use_attachment]": "true", "filter[execution_type]": "firewall,email_infiltration", "start_drange": start.Format(time.RFC3339), "end_drange": end.Format(time.RFC3339), "filter[start_release_date]": start.Format(time.RFC3339), "filter[end_release_date]": end.Format(time.RFC3339)} {
		if query.Get(key) != want {
			t.Errorf("ListCampaigns query[%q] = %q, want %q", key, query.Get(key), want)
		}
	}
	got, err := GetCampaign(t.Context(), h, "campaign-id", GetCampaignOpts{AnalyticsOpts: AnalyticsOpts{Days: new(uint(0)), UseLink: new(false)}})
	if err != nil {
		t.Fatalf("GetCampaign = %v, want nil", err)
	}
	query = <-queries
	if err != nil || got.ID != "campaign-id" || query.Get("d") != "0" || query.Get("filter[use_link]") != "false" {
		t.Errorf("GetCampaign = %+v, %v, query=%v, want campaign-id and explicit zero/false filters", got, err, query)
	}
	filters, err := GetCampaignFilters(t.Context(), h, filter)
	if err != nil {
		t.Fatalf("GetCampaignFilters = %v, want nil", err)
	}
	query = <-queries
	if err != nil || len(filters.Family) != 1 || filters.Family[0].Count != 2 || query.Get("filter[family]") != "first,second" {
		t.Errorf("GetCampaignFilters = %+v, %v, query=%v, want family values and metadata filters", filters, err, query)
	}
	_, err = ListCampaigns(t.Context(), h, ListCampaignsOpts{})
	if err != nil {
		t.Fatalf("ListCampaigns(zero opts) = %v, want nil", err)
	}
	query = <-queries
	if err != nil || query.Has("size") || query.Has("offset") || query.Has("d") || query.Has("filter[use_link]") {
		t.Errorf("ListCampaigns(zero opts) = %v, query=%v, want server defaults", err, query)
	}
}

func TestCampaignErrorsAndValidation(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		campaignJSON(t, w, 403, `{"status":403,"title":"user_emerging_threats required"}`)
	})
	_, err := GetCampaign(t.Context(), h, "campaign-id", GetCampaignOpts{})
	problem, ok := errors.AsType[*api.APIError](err)
	if !ok || problem.Status != 403 || !strings.Contains(err.Error(), "user_emerging_threats") {
		t.Errorf("GetCampaign(forbidden) = %v, want typed feature denial", err)
	}
	for _, id := range []string{"", "..", "../other", "a/b", "a?query=bad"} {
		if _, err := GetCampaign(t.Context(), h, id, GetCampaignOpts{}); err == nil || errors.Is(err, api.ErrApiKeyInvalid) {
			t.Errorf("GetCampaign(id=%q) = %v, want local validation error", id, err)
		}
	}
	if _, err := ListCampaigns(t.Context(), h, ListCampaignsOpts{Offset: -1}); err == nil {
		t.Error("ListCampaigns(offset=-1) error = nil, want validation error")
	}
	if _, err := GetCampaign(t.Context(), h, "id", GetCampaignOpts{AnalyticsOpts: AnalyticsOpts{StartDayRange: time.Now()}}); err == nil {
		t.Error("GetCampaign(incomplete range) error = nil, want validation error")
	}
}
