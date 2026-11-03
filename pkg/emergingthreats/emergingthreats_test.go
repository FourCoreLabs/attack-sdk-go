package emergingthreats

import (
	"context"
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
	"github.com/fourcorelabs/attack-sdk-go/pkg/executions"
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

func TestV2CatalogReportAndExecutionRoutes(t *testing.T) {
	attackRun := model.RunAttackRequest{AttackPayloads: []string{"threat-id"}, Assets: []string{"asset-id"}}
	campaignRun := model.RunCampaignRequest{Campaigns: []string{"campaign-id"}, Assets: []string{"asset-id"}}
	tests := []struct {
		name, method, path, body string
		call                     func(*api.HTTPAPI) error
	}{
		{"catalog list", "GET", "/api/v2/content/emerging_threat", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error {
			_, err := ListCatalogThreats(t.Context(), h, ListCatalogThreatsOpts{})
			return err
		}},
		{"catalog detail", "GET", "/api/v2/content/emerging_threat/threat-id", `{}`, func(h *api.HTTPAPI) error {
			_, err := GetCatalogThreat(t.Context(), h, "threat-id", AnalyticsOpts{})
			return err
		}},
		{"catalog filters", "GET", "/api/v2/content/emerging_threat/filters", `{}`, func(h *api.HTTPAPI) error { _, err := GetCatalogFilters(t.Context(), h, CatalogFilter{}); return err }},
		{"catalog groups", "GET", "/api/v2/content/emerging_threat/group/family", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error {
			_, err := ListCatalogGroups(t.Context(), h, GroupByFamily, ListCatalogThreatsOpts{})
			return err
		}},
		{"malware categories", "GET", "/api/v2/content/emerging_threat/malware_category", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error {
			_, err := ListMalwareCategories(t.Context(), h, ListMalwareCategoriesOpts{})
			return err
		}},
		{"overview", "GET", "/api/v2/content/emerging_threat/overview/analytics", `{}`, func(h *api.HTTPAPI) error { _, err := GetOverviewAnalytics(t.Context(), h, OverviewOpts{}); return err }},
		{"payload overview", "GET", "/api/v2/content/emerging_threat/overview/payload_analytics", `{}`, func(h *api.HTTPAPI) error {
			_, err := GetOverviewPayloadAnalytics(t.Context(), h, OverviewOpts{})
			return err
		}},
		{"vector overview", "GET", "/api/v2/content/emerging_threat/overview/vector_analytics", `{}`, func(h *api.HTTPAPI) error {
			_, err := GetOverviewVectorAnalytics(t.Context(), h, OverviewOpts{})
			return err
		}},
		{"catalog campaigns", "GET", "/api/v2/content/emerging_threat_campaigns", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error {
			_, err := ListCatalogCampaigns(t.Context(), h, ListCatalogCampaignsOpts{})
			return err
		}},
		{"catalog campaign", "GET", "/api/v2/content/emerging_threat_campaigns/campaign-id", `{}`, func(h *api.HTTPAPI) error {
			_, err := GetCatalogCampaign(t.Context(), h, "campaign-id", AnalyticsOpts{})
			return err
		}},
		{"catalog campaign filters", "GET", "/api/v2/content/emerging_threat_campaigns/filters", `{}`, func(h *api.HTTPAPI) error {
			_, err := GetCatalogCampaignFilters(t.Context(), h, CatalogCampaignFilter{})
			return err
		}},
		{"catalog indicators", "GET", "/api/v2/content/emerging_threat_campaigns/campaign-id/indicators", `{}`, func(h *api.HTTPAPI) error {
			_, err := GetCatalogCampaignIndicators(t.Context(), h, "campaign-id")
			return err
		}},
		{"reports", "GET", "/api/v2/emerging_threat/reports", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error { _, err := ListReports(t.Context(), h, ListReportsOpts{}); return err }},
		{"report", "GET", "/api/v2/emerging_threat/reports/run-id", `{}`, func(h *api.HTTPAPI) error { _, err := GetReport(t.Context(), h, "run-id"); return err }},
		{"delete report", "DELETE", "/api/v2/emerging_threat/reports/run-id", `{"success":true,"id":"run-id"}`, func(h *api.HTTPAPI) error { _, err := DeleteReport(t.Context(), h, "run-id"); return err }},
		{"campaign reports", "GET", "/api/v2/emerging_threat/campaign/reports", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error {
			_, err := ListCampaignReports(t.Context(), h, ListCampaignReportsOpts{})
			return err
		}},
		{"campaign report", "GET", "/api/v2/emerging_threat/campaign/reports/run-id", `{}`, func(h *api.HTTPAPI) error { _, err := GetCampaignReport(t.Context(), h, "run-id"); return err }},
		{"delete campaign report", "DELETE", "/api/v2/emerging_threat/campaign/reports/run-id", `{"success":true,"id":"run-id"}`, func(h *api.HTTPAPI) error { _, err := DeleteCampaignReport(t.Context(), h, "run-id"); return err }},
		{"run catalog threats", "POST", "/api/v2/emerging_threat/run", `[]`, func(h *api.HTTPAPI) error { _, err := RunCatalogThreats(t.Context(), h, attackRun); return err }},
		{"run conditional threats", "POST", "/api/v2/emerging_threat/run/condition", `{}`, func(h *api.HTTPAPI) error {
			_, err := RunConditionalCatalogThreats(t.Context(), h, model.RunConditionalRequest{RunAttackRequest: attackRun})
			return err
		}},
		{"run catalog campaign", "POST", "/api/v2/emerging_threat/campaign/campaign-id/run", `{}`, func(h *api.HTTPAPI) error {
			_, err := RunCatalogCampaign(t.Context(), h, "campaign-id", campaignRun)
			return err
		}},
		{"run catalog campaigns", "POST", "/api/v2/emerging_threat/campaign/run", `[]`, func(h *api.HTTPAPI) error { _, err := RunCatalogCampaigns(t.Context(), h, campaignRun); return err }},
		{"abort run", "POST", "/api/v2/emerging_threat/runs/run-id/abort", `{"success":true,"id":"run-id"}`, func(h *api.HTTPAPI) error { _, err := AbortRun(t.Context(), h, "run-id"); return err }},
		{"abort campaign", "POST", "/api/v2/emerging_threat/campaign/reports/run-id/abort", `{"success":true,"id":"run-id"}`, func(h *api.HTTPAPI) error { _, err := AbortCampaignRun(t.Context(), h, "run-id"); return err }},
		{"all executions", "GET", "/api/v2/executions/all", `{"data":[],"total_rows":0}`, func(h *api.HTTPAPI) error {
			_, err := executions.ListAllExecutions(t.Context(), h, executions.ListAllExecutionsOpts{})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != test.method || r.URL.Path != test.path || r.Header.Get("Authorization") != "Bearer campaign-key" {
					t.Errorf("got %s %s, want %s %s with API key", r.Method, r.URL.Path, test.method, test.path)
				}
				campaignJSON(t, w, 200, test.body)
			})
			if err := test.call(h); err != nil {
				t.Fatal(err)
			}
		})
	}
	if AttacksV2URI != "/api/v2/emerging_threat/attack" || CampaignsV2URI != "/api/v2/emerging_threat/attack/campaigns" {
		t.Fatal("authored threat routes do not match the renamed server routes")
	}
}

func TestCatalogQueryAndDecode(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		want := map[string]string{
			"size": "20", "offset": "2", "order": "-release_date,name",
			"filter[family]": "alpha,beta", "filter[hosting]": "provider", "filter[domain]": "example.test",
			"filter[show_deprecated]": "false", "filter[start_success_percent]": "0", "filter[end_success_percent]": "100",
			"filter[use_link]": "false", "filter[use_attachment]": "true", "filter[execution_type]": "firewall,email_infiltration",
			"start_drange": start.Format(time.RFC3339), "end_drange": start.Add(24 * time.Hour).Format(time.RFC3339),
		}
		for key, value := range want {
			if r.URL.Query().Get(key) != value || len(r.URL.Query()[key]) != 1 {
				t.Errorf("query %s = %v, want one %q", key, r.URL.Query()[key], value)
			}
		}
		campaignJSON(t, w, 200, `{"total_rows":1,"size":20,"data":[{"id":"payload-id","text":"catalog description","type":"host","behaviour_analytics":{"web_proxy_url_request":{"count":1,"total":2,"success":1}}}]}`)
	})
	result, err := ListCatalogThreats(t.Context(), h, ListCatalogThreatsOpts{
		Size: 20, Offset: 2, Order: "-release_date,name", Family: []string{"alpha", "beta"},
		Hosting: []string{"provider"}, Domain: []string{"example.test"}, ShowDeprecated: new(false),
		StartSuccessPercent: new(uint(0)), EndSuccessPercent: new(uint(100)),
		StartDayRange: start, EndDayRange: start.Add(24 * time.Hour), UseLink: new(false), UseAttachment: new(true),
		ExecutionType: []string{"firewall", "email_infiltration"},
	})
	if err != nil || result.TotalRows != 1 || len(result.Data) != 1 || result.Data[0].Description != "catalog description" || result.Data[0].BehaviourAnalytics.WebProxyURLRequest.Success != 1 {
		t.Fatalf("catalog response = %+v, err = %v", result, err)
	}
}

func TestCampaignCatalogFiltersAndOverview(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == CatalogCampaignsV2URI+"/filters" {
			for key, want := range map[string]string{
				"filter[industry]": "energy,finance", "filter[threat_actor]": "actor", "filter[hide_empty]": "false",
				"filter[region]": "region:Europe", "filter[show_deprecated]": "true", "filter[hosting]": "provider",
			} {
				if r.URL.Query().Get(key) != want {
					t.Errorf("%s = %q, want %q", key, r.URL.Query().Get(key), want)
				}
			}
			campaignJSON(t, w, 200, `{"hosting_org":[{"count":2,"data":"provider"}],"region_country":[{"count":1,"data":"country:France"}]}`)
			return
		}
		if r.URL.Query().Get("filter[start_timestamp]") != start.Format(time.RFC3339) || r.URL.Query().Get("filter[end_timestamp]") != start.Add(time.Hour).Format(time.RFC3339) {
			t.Errorf("overview query = %v", r.URL.Query())
		}
		campaignJSON(t, w, 200, `{"analytics":[{"file_type":"exe","success_count":2}],"total_success_count":2}`)
	})
	filters, err := GetCatalogCampaignFilters(t.Context(), h, CatalogCampaignFilter{
		Industry: []string{"energy", "finance"}, Region: []string{"region:Europe"}, ThreatActor: []string{"actor"},
		HideEmpty: new(false), ShowDeprecated: new(true), Hosting: []string{"provider"},
	})
	if err != nil || len(filters.HostingOrg) != 1 || filters.HostingOrg[0].Count != 2 || len(filters.RegionCountry) != 1 {
		t.Fatalf("filters=%+v, err=%v", filters, err)
	}
	overview, err := GetOverviewPayloadAnalytics(t.Context(), h, OverviewOpts{StartTimestamp: start, EndTimestamp: start.Add(time.Hour)})
	if err != nil || overview.TotalSuccessCount != 2 || len(overview.Analytics) != 1 || overview.Analytics[0].FileType != "exe" {
		t.Fatalf("overview=%+v, err=%v", overview, err)
	}
}

func TestReportFiltersDetailsAndErrors(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case CampaignReportsV2URI:
			for key, want := range map[string]string{
				"size": "5", "order": "-updated_at", "filter[name]": "report", "filter[user_id]": "2,3",
				"filter[campaign_id]": "catalog,user-campaign", "filter[asset_id]": "asset-id", "filter[schedule_id]": "schedule-id",
				"filter[group_campaign_run_id]": "group-id", "filter[behaviours]": "malicious_url_request", "d": "7",
			} {
				if r.URL.Query().Get(key) != want {
					t.Errorf("%s=%q, want %q", key, r.URL.Query().Get(key), want)
				}
			}
			campaignJSON(t, w, 200, `{"total_rows":1,"data":[{"id":"campaign-run","schedule_id":{"String":"schedule-id","Valid":true},"attack_payload_executions":[{"id":"run-id"}]}]}`)
		case ReportsV2URI + "/gone":
			campaignJSON(t, w, 410, `{"status":410,"title":"report deleted by user"}`)
		default:
			campaignJSON(t, w, 200, `{"id":"run-id","schedule_id":{"String":"schedule-id","Valid":true},"steps":[{"execution_id":"execution-id","success_assets":1,"use_link":true,"assets":[{"asset_id":"asset-id","status":"finished","total_success":1}]}]}`)
		}
	})
	page, err := ListCampaignReports(t.Context(), h, ListCampaignReportsOpts{
		Size: 5, Order: "-updated_at", Name: "report", UserIDs: []uint{2, 3}, CampaignIDs: []string{"catalog", "user-campaign"},
		AssetIDs: []string{"asset-id"}, ScheduleIDs: []string{"schedule-id"}, GroupCampaignRunIDs: []string{"group-id"},
		Behaviours: []string{"malicious_url_request"}, Days: new(uint(7)),
	})
	if err != nil || len(page.Data) != 1 || page.Data[0].AttackPayloadExecutions[0].ID != "run-id" || !page.Data[0].ScheduleID.Valid {
		t.Fatalf("campaign reports=%+v, err=%v", page, err)
	}
	report, err := GetReport(t.Context(), h, "run-id")
	if err != nil || len(report.Steps) != 1 || report.Steps[0].SuccessAssets != 1 || report.Steps[0].Assets[0].TotalSuccess != 1 {
		t.Fatalf("report=%+v, err=%v", report, err)
	}
	_, err = GetReport(t.Context(), h, "gone")
	problem, ok := errors.AsType[*api.APIError](err)
	if !ok || problem.Status != 410 || problem.Title != "report deleted by user" {
		t.Fatalf("gone error=%v", err)
	}
}

func TestCombinedReportFiltersAndDecode(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		for key, want := range map[string]string{
			"filter[execution_group_type]": "emerging_threat,playbook", "filter[action_id]": "a,b",
			"filter[user_id]": "1,2", "filter[use_attachment]": "false", "filter[start_blocked_percent]": "0", "size": "15",
		} {
			if r.URL.Query().Get(key) != want {
				t.Errorf("%s = %q, want %q", key, r.URL.Query().Get(key), want)
			}
		}
		campaignJSON(t, w, 200, `{"total_rows":1,"data":[{"run_id":"run-id","group_type":"emerging_threat","execution_type":["firewall"],"schedule_id":{"String":"schedule-id","Valid":true},"behaviour_analytics":{"behaviours":[{"id":"payload-id","use_link":true,"success":1}]}}]}`)
	})
	result, err := executions.ListAllExecutions(t.Context(), h, executions.ListAllExecutionsOpts{
		Size: 15, ExecutionGroupTypes: []string{"emerging_threat", "playbook"}, ActionIDs: []string{"a", "b"},
		UserIDs: []uint{1, 2}, UseAttachment: new(false), StartBlockedPercent: new(uint(0)),
	})
	if err != nil || result.TotalRows != 1 || len(result.Data) != 1 || result.Data[0].RunID != "run-id" || result.Data[0].ScheduleID.String != "schedule-id" || !result.Data[0].ScheduleID.Valid || len(result.Data[0].BehaviourAnalytics.Behaviours) != 1 {
		t.Fatalf("combined reports = %+v, err = %v", result, err)
	}
}

func TestConditionalExecutionBodyAndNoContentCampaign(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/emerging_threat/campaign/user/run" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var request struct {
			Filters []struct {
				Name  string   `json:"name"`
				Value []string `json:"value"`
			} `json:"filter_by"`
		}
		if err := json.Unmarshal(body, &request); err != nil || len(request.Filters) != 1 || request.Filters[0].Name != "family" || request.Filters[0].Value[0] != "alpha" {
			t.Errorf("conditional body = %s, err=%v", body, err)
		}
		campaignJSON(t, w, 200, `{"id":"group-run"}`)
	})
	result, err := RunConditionalCatalogThreats(t.Context(), h, model.RunConditionalRequest{
		Assets: []string{"asset-id"}, FilterBy: []model.Condition{{Name: "family", Value: []string{"alpha"}}},
	})
	if err != nil || result.ID != "group-run" {
		t.Fatalf("conditional run = %+v, err=%v", result, err)
	}
	runs, err := RunCampaigns(t.Context(), h, model.RunCampaignRequest{Campaigns: []string{"empty"}, Assets: []string{"asset-id"}})
	if err != nil || len(runs) != 0 {
		t.Fatalf("empty campaign runs = %+v, err=%v", runs, err)
	}
}

func TestWatchRunEventsAndClose(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/emerging_threat/runs/run-id/sse" || r.Header.Get("Accept") != "text/event-stream" || r.Header.Get("Authorization") != "Bearer campaign-key" {
			t.Errorf("unexpected SSE request %s %v", r.URL, r.Header)
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = io.WriteString(w, ": comment\r\nevent: retry\r\nretry: 1000\r\n\r\nid: 1\nevent: status-update\ndata: first\ndata: second\n\nevent: keep_alive\ndata: \n\nevent: close\ndata: execution complete\n\n")
	})
	var events []RunEvent
	for event, err := range WatchRun(t.Context(), h, "run-id") {
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 4 || events[0].Retry != time.Second || events[1].Data != "first\nsecond" || events[1].ID != "1" || events[3].Type != "close" {
		t.Fatalf("events = %+v", events)
	}
}

func TestWatchRunCancellationAndHTTPError(t *testing.T) {
	t.Run("early break closes body", func(t *testing.T) {
		done := make(chan struct{})
		h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: status-update\ndata: \n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(done)
		})
		for _, err := range WatchRun(t.Context(), h, "run-id") {
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("stream body not closed")
		}
	})
	t.Run("HTTP error", func(t *testing.T) {
		h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			campaignJSON(t, w, 403, `{"title":"forbidden","status":403}`)
		})
		for _, err := range WatchRun(t.Context(), h, "run-id") {
			if !errors.Is(err, api.ErrApiKeyInvalid) {
				t.Fatalf("error = %v", err)
			}
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled request sent") })
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		for _, err := range WatchRun(ctx, h, "run-id") {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
		}
	})
}

func TestNewAPILocalValidation(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid input sent a request") })
	for _, id := range []string{"", ".", "..", "a/b", "id?filter=bad"} {
		if _, err := GetReport(t.Context(), h, id); err == nil {
			t.Errorf("accepted report ID %q", id)
		}
		if _, err := GetCatalogCampaign(t.Context(), h, id, AnalyticsOpts{}); err == nil {
			t.Errorf("accepted campaign ID %q", id)
		}
	}
	if _, err := ListCatalogGroups(t.Context(), h, "unsupported", ListCatalogThreatsOpts{}); err == nil {
		t.Error("accepted invalid grouping")
	}
	if _, err := ListCatalogThreats(t.Context(), h, ListCatalogThreatsOpts{Size: -1}); err == nil {
		t.Error("accepted negative page size")
	}
	if _, err := ListCatalogThreats(t.Context(), h, ListCatalogThreatsOpts{Order: "-"}); err == nil {
		t.Error("accepted invalid sort")
	}
	if _, err := executions.ListAllExecutions(t.Context(), h, executions.ListAllExecutionsOpts{StartSuccessPercent: new(uint(101))}); err == nil {
		t.Error("accepted percentage >100")
	}
	if _, err := RunCatalogThreats(t.Context(), h, model.RunAttackRequest{}); err == nil {
		t.Error("accepted empty execution")
	}
	if _, err := GetOverviewAnalytics(t.Context(), h, OverviewOpts{StartDayRange: time.Now()}); err == nil {
		t.Error("accepted incomplete date range")
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
