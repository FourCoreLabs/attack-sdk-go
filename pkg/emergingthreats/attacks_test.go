package emergingthreats

import (
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
)

func TestCreateAndUpdateAttack(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				wantPath := AttacksV2URI
				if method == http.MethodPut {
					wantPath += "/attack-id"
				}
				if r.Method != method || r.URL.Path != wantPath || r.Header.Get("Authorization") != "Bearer campaign-key" {
					t.Errorf("attack write = %s %s headers=%v, want %s %s with API key", r.Method, r.URL.Path, r.Header, method, wantPath)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read attack request = %v, want nil", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var request struct {
					Name        string `json:"name"`
					PayloadType string `json:"payload_type"`
					Payload     struct {
						Object string `json:"object"`
					} `json:"payload"`
					Family  string `json:"family"`
					DeleteF *bool  `json:"delete_tenant_file_on_no_relation"`
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Errorf("decode attack request = %v, want nil", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if request.Name != "IOC entry" || request.PayloadType != model.PayloadTypeObject ||
					request.Payload.Object != "tenant://bucket/org/file-id" || request.Family != "sample" {
					t.Errorf("attack write document = %+v, want standalone object entry", request)
				}
				if method == http.MethodPut && (request.DeleteF == nil || *request.DeleteF) {
					t.Errorf("update cleanup flag = %v, want explicit false", request.DeleteF)
				}
				status := http.StatusOK
				if method == http.MethodPost {
					status = http.StatusCreated
				}
				campaignJSON(t, w, status, `{"id":"attack-id","name":"IOC entry","text":"entry description","type":"object","payload":{"object":"tenant://bucket/org/file-id","attachment_name":"sample.bin"},"family":"sample","total_host":0,"total_malware":1}`)
			})

			entry := model.AttackInput{
				Name: "IOC entry", Description: "entry description",
				PayloadType: model.PayloadTypeObject,
				Payload:     model.Payload{Object: "tenant://bucket/org/file-id"},
				Family:      "sample",
			}
			var result model.Attack
			var err error
			if method == http.MethodPost {
				result, err = CreateAttack(t.Context(), h, entry)
			} else {
				result, err = UpdateAttack(t.Context(), h, "attack-id", model.AttackUpdateRequest{AttackInput: entry})
			}
			if err != nil {
				t.Fatalf("attack write(%s) = %v, want nil", method, err)
			}
			if result.ID != "attack-id" || result.Description != "entry description" ||
				result.Payload.AttachmentName != "sample.bin" || result.TotalMalware != 1 {
				t.Errorf("attack write(%s) result = %+v, want complete standalone entry", method, result)
			}
		})
	}
}

func TestDeleteAttackOptionalCleanup(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(strconv.FormatBool(explicit), func(t *testing.T) {
			h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != AttacksV2URI+"/attack-id" {
					t.Errorf("DeleteAttack request = %s %s, want DELETE attack-id", r.Method, r.URL.Path)
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
						t.Errorf("DeleteAttack body = %q, %v, want explicit false cleanup", body, err)
					}
				} else if len(body) != 0 {
					t.Errorf("DeleteAttack(nil) body = %q, want no body", body)
				}
				campaignJSON(t, w, 200, `{"success":true,"id":"attack-id"}`)
			})

			var request *model.AttackDeleteRequest
			if explicit {
				request = &model.AttackDeleteRequest{DeleteTenantFileOnNoRelation: new(false)}
			}
			result, err := DeleteAttack(t.Context(), h, "attack-id", request)
			if err != nil || !result.Success || result.ID != "attack-id" {
				t.Errorf("DeleteAttack(explicit=%t) = %+v, %v, want successful attack-id", explicit, result, err)
			}
		})
	}
}

func TestListGetAndFilterAttackQueries(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 7)
	queries := make(chan url.Values, 3)
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.Query()
		if r.Method != http.MethodGet {
			t.Errorf("attack read method = %s, want GET", r.Method)
		}
		switch r.URL.Path {
		case AttacksV2URI:
			campaignJSON(t, w, 200, `{"size":10,"total_rows":1,"data":[{"id":"attack-id","type":"host"}]}`)
		case AttacksV2URI + "/attack-id":
			campaignJSON(t, w, 200, `{"id":"attack-id"}`)
		case AttacksV2URI + "/filters":
			campaignJSON(t, w, 200, `{"payload_type":["malware","host"],"family":["sample"]}`)
		default:
			t.Errorf("attack read path = %s, want attack route", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	filter := AttackFilter{Family: []string{"first", "second"}, PayloadType: []string{"host"}}
	listed, err := ListAttacks(t.Context(), h, ListAttacksOpts{
		AttackFilter:  filter,
		AnalyticsOpts: AnalyticsOpts{StartDayRange: start, EndDayRange: end, UseAttachment: new(false)},
		Size:          10,
		Offset:        5,
		Order:         "-updated_at",
	})
	if err != nil || listed.TotalRows != 1 || len(listed.Data) != 1 {
		t.Fatalf("ListAttacks = %+v, %v, want one attack", listed, err)
	}
	query := <-queries
	for key, want := range map[string]string{
		"size": "10", "offset": "5", "order": "-updated_at",
		"filter[family]": "first,second", "filter[payload_type]": "host",
		"start_drange": start.Format(time.RFC3339), "end_drange": end.Format(time.RFC3339),
		"filter[use_attachment]": "false",
	} {
		if query.Get(key) != want {
			t.Errorf("ListAttacks query[%q] = %q, want %q", key, query.Get(key), want)
		}
	}

	got, err := GetAttack(t.Context(), h, "attack-id", GetAttackOpts{AnalyticsOpts: AnalyticsOpts{Days: new(uint(7)), UseLink: new(true)}})
	if err != nil {
		t.Fatalf("GetAttack = %v, want nil", err)
	}
	query = <-queries
	if got.ID != "attack-id" || query.Get("d") != "7" || query.Get("filter[use_link]") != "true" {
		t.Errorf("GetAttack = %+v, query=%v, want attack-id and analytics filters", got, query)
	}

	filters, err := GetAttackFilters(t.Context(), h, filter)
	if err != nil {
		t.Fatalf("GetAttackFilters = %v, want nil", err)
	}
	query = <-queries
	if len(filters.PayloadType) != 2 || len(filters.Family) != 1 || query.Get("filter[family]") != "first,second" {
		t.Errorf("GetAttackFilters = %+v, query=%v, want dropdown values and metadata filters", filters, query)
	}
}

func TestRunAttackAndCampaignRequests(t *testing.T) {
	requests := make(chan map[string]any, 3)
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer campaign-key" {
			t.Errorf("run request = %s %s, want POST with API key", r.Method, r.URL.Path)
		}
		var body map[string]any
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read run body = %v, want nil", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode run body = %v, want nil", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- body
		switch r.URL.Path {
		case ExecuteAttacksV2URI + "/run", ExecuteAttacksV2URI + "/attack-id/run":
			campaignJSON(t, w, 200, `[{"id":"run-id","emerging_threat_attack_id":"attack-id","status":"queued","total_attacks":2,"asset_id":["endpoint-1"]}]`)
		case ExecuteCampaignsV2URI + "/run":
			campaignJSON(t, w, 200, `[{"id":"campaign-run-id","campaign_id":"campaign-id","total_malwares":3,"attack_payload_executions":[{"id":"run-id"}]}]`)
		default:
			t.Errorf("run path = %s, want execution route", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	runRequest := model.RunAttackRequest{
		AttackPayloads: []string{"attack-id"},
		Assets:         []string{"endpoint-1"},
		RunElevated:    new(true),
		DisableCleanup: new(false),
		Behaviours:     &model.BehaviourOpts{WebProxyURLRequest: true},
	}
	bulk, err := RunAttacks(t.Context(), h, runRequest)
	if err != nil || len(bulk) != 1 || bulk[0].EmergingThreatAttackID != "attack-id" || bulk[0].TotalAttacks != 2 {
		t.Fatalf("RunAttacks = %+v, %v, want one decoded attack run", bulk, err)
	}
	body := <-requests
	if payloads, ok := body["attack_payloads"].([]any); !ok || len(payloads) != 1 || payloads[0] != "attack-id" {
		t.Errorf("RunAttacks attack_payloads = %v, want [attack-id]", body["attack_payloads"])
	}
	if body["run_elevated"] != true {
		t.Errorf("RunAttacks run_elevated = %v, want true", body["run_elevated"])
	}
	if behaviours, ok := body["behaviours"].(map[string]any); !ok || behaviours["web_proxy_url_request"] != true {
		t.Errorf("RunAttacks behaviours = %v, want web_proxy_url_request", body["behaviours"])
	}

	single, err := RunAttack(t.Context(), h, "attack-id", runRequest)
	if err != nil || len(single) != 1 {
		t.Fatalf("RunAttack = %+v, %v, want one decoded attack run", single, err)
	}
	body = <-requests
	if _, ok := body["attack_payloads"]; ok {
		t.Errorf("RunAttack body = %v, want body threat IDs dropped in favour of the path", body)
	}

	runs, err := RunCampaigns(t.Context(), h, model.RunCampaignRequest{
		Campaigns:   []string{"campaign-id"},
		EmailAssets: []string{"email-1"},
	})
	if err != nil || len(runs) != 1 || runs[0].CampaignID != "campaign-id" ||
		runs[0].TotalMalwares != 3 || len(runs[0].AttackPayloadExecutions) != 1 {
		t.Fatalf("RunCampaigns = %+v, %v, want one decoded campaign run", runs, err)
	}
	body = <-requests
	if campaigns, ok := body["campaigns"].([]any); !ok || len(campaigns) != 1 || campaigns[0] != "campaign-id" {
		t.Errorf("RunCampaigns campaigns = %v, want [campaign-id]", body["campaigns"])
	}
}

func TestAttackRunValidationAndErrors(t *testing.T) {
	h := campaignTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		campaignJSON(t, w, 404, `{"status":404,"title":"emerging threat not found"}`)
	})

	for _, id := range []string{"", "..", "../other", "a/b", "a?query=bad"} {
		if _, err := GetAttack(t.Context(), h, id, GetAttackOpts{}); err == nil {
			t.Errorf("GetAttack(id=%q) error = nil, want local validation error", id)
		}
		if _, err := RunAttack(t.Context(), h, id, model.RunAttackRequest{Assets: []string{"endpoint-1"}}); err == nil {
			t.Errorf("RunAttack(id=%q) error = nil, want local validation error", id)
		}
	}

	for _, test := range []struct {
		name string
		run  func() error
	}{
		{name: "attacks without assets", run: func() error {
			_, err := RunAttacks(t.Context(), h, model.RunAttackRequest{AttackPayloads: []string{"attack-id"}})
			return err
		}},
		{name: "attacks without payloads", run: func() error {
			_, err := RunAttacks(t.Context(), h, model.RunAttackRequest{Assets: []string{"endpoint-1"}})
			return err
		}},
		{name: "attacks with an empty payload ID", run: func() error {
			_, err := RunAttacks(t.Context(), h, model.RunAttackRequest{AttackPayloads: []string{""}, Assets: []string{"endpoint-1"}})
			return err
		}},
		{name: "attack run with an empty asset ID", run: func() error {
			_, err := RunAttack(t.Context(), h, "attack-id", model.RunAttackRequest{Assets: []string{""}})
			return err
		}},
		{name: "campaigns without assets", run: func() error {
			_, err := RunCampaigns(t.Context(), h, model.RunCampaignRequest{Campaigns: []string{"campaign-id"}})
			return err
		}},
		{name: "campaigns without IDs", run: func() error {
			_, err := RunCampaigns(t.Context(), h, model.RunCampaignRequest{Assets: []string{"endpoint-1"}})
			return err
		}},
		{name: "campaigns with an empty campaign ID", run: func() error {
			_, err := RunCampaigns(t.Context(), h, model.RunCampaignRequest{Campaigns: []string{""}, EmailAssets: []string{"email-1"}})
			return err
		}},
		{name: "negative size", run: func() error {
			_, err := ListAttacks(t.Context(), h, ListAttacksOpts{Size: -1})
			return err
		}},
		{name: "incomplete analytics range", run: func() error {
			_, err := GetAttack(t.Context(), h, "attack-id", GetAttackOpts{AnalyticsOpts: AnalyticsOpts{StartDayRange: time.Now()}})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Errorf("%s error = nil, want local validation error", test.name)
			}
		})
	}

	_, err := GetAttack(t.Context(), h, "attack-id", GetAttackOpts{})
	problem, ok := errors.AsType[*api.APIError](err)
	if !ok || problem.Status != http.StatusNotFound {
		t.Errorf("GetAttack(missing) = %v, want typed API error", err)
	}
}
