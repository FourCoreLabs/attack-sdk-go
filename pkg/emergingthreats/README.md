# Emerging threats: v2 SDK

`pkg/emergingthreats` separates **catalog threats** (FourCore content) from
**authored attacks/campaigns** (your organization's saved IOCs). Functions take
`context.Context` and `*api.HTTPAPI`; response types live in
`pkg/models/emergingthreats`.

## Catalog

| Function | GET endpoint |
|---|---|
| `ListCatalogThreats` | `/api/v2/content/emerging_threat` |
| `GetCatalogThreat` | `/api/v2/content/emerging_threat/:attack_payload_id` |
| `GetCatalogFilters` | `/api/v2/content/emerging_threat/filters` |
| `ListCatalogGroups` | `/api/v2/content/emerging_threat/group/:type` |
| `ListMalwareCategories` | `/api/v2/content/emerging_threat/malware_category` |
| `GetOverviewAnalytics` | `/api/v2/content/emerging_threat/overview/analytics` |
| `GetOverviewPayloadAnalytics` | `/api/v2/content/emerging_threat/overview/payload_analytics` |
| `GetOverviewVectorAnalytics` | `/api/v2/content/emerging_threat/overview/vector_analytics` |
| `ListCatalogCampaigns` | `/api/v2/content/emerging_threat_campaigns` |
| `GetCatalogCampaign` | `/api/v2/content/emerging_threat_campaigns/:campaign_id` |
| `GetCatalogCampaignFilters` | `/api/v2/content/emerging_threat_campaigns/filters` |
| `GetCatalogCampaignIndicators` | `/api/v2/content/emerging_threat_campaigns/:campaign_id/indicators` |

These require `emergingthreat.read` and the `emerging_threats` feature. Deprecated
overview and threat-hunting automation endpoints are deliberately not included.

```go
client, err := api.NewHTTPAPI(baseURL, apiKey)
if err != nil {
    return err
}

page, err := emergingthreats.ListCatalogThreats(ctx, client,
    emergingthreats.ListCatalogThreatsOpts{
        Size:                20,
        Order:               "-release_date,name",
        Types:               []string{model.PayloadTypeHost},
        Family:              []string{"example-family"},
        UseLink:             new(true),
        UseAttachment:       new(false),
        StartSuccessPercent: new(uint(0)),
    })
if err != nil {
    return err
}
for _, threat := range page.Data {
    fmt.Println(threat.ID, threat.Name)
}
```

Here `model` is `github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats`.
Examples use Go 1.27's promoted-field literals and `new(value)` syntax, matching
this module's Go version.

- A zero page size omits the parameter and uses the server default.
- Use `page.TotalRows` plus `Size`/`Offset` for paging; functions return one page.
- Nil boolean/percentage pointers omit the filter. `new(false)` and `new(uint(0))`
  explicitly filter false/zero.
- Set both `StartDayRange` and `EndDayRange`, or use `Days`. Times use RFC3339.
- Catalog `Hosting`/`Domain` filters differ from authored-threat
  `HostingOrganisation`/`DomainName` filters.
- `GetCatalogCampaignIndicators` returns derived observables and a `NotChecked`
  count; it does not run a hunt.

## Authored IOC attacks and campaigns

Existing public functions keep their names but use the renamed server paths:

| Functions | Base endpoint |
|---|---|
| `CreateAttack`, `UpdateAttack`, `DeleteAttack`, `ListAttacks`, `GetAttack`, `GetAttackFilters` | `/api/v2/emerging_threat/attack` |
| `CreateCampaign`, `UpdateCampaign`, `DeleteCampaign`, `ListCampaigns`, `GetCampaign`, `GetCampaignFilters` | `/api/v2/emerging_threat/attack/campaigns` |

They require the matching `useremergingthreats.create/read/update/delete`
permission and `user_emerging_threats` feature. Existing request/model types are
unchanged apart from additional response fields.

## Execution and run control

| Function | POST endpoint |
|---|---|
| `RunCatalogThreats` | `/api/v2/emerging_threat/run` |
| `RunConditionalCatalogThreats` | `/api/v2/emerging_threat/run/condition` |
| `RunCatalogCampaign` | `/api/v2/emerging_threat/campaign/:campaign_id/run` |
| `RunCatalogCampaigns` | `/api/v2/emerging_threat/campaign/run` |
| `RunAttacks` | `/api/v2/emerging_threat/user/run` |
| `RunAttack` | `/api/v2/emerging_threat/user/:attack_id/run` |
| `RunCampaigns` | `/api/v2/emerging_threat/campaign/user/run` |
| `AbortRun` | `/api/v2/emerging_threat/runs/:run_id/abort` |
| `AbortCampaignRun` | `/api/v2/emerging_threat/campaign/reports/:run_id/abort` |

Catalog runs and aborts require `emergingthreat.execute`; authored runs require
`useremergingthreats.execute`. Launching runs requires execution to be enabled.
Pass at least one endpoint or email asset. Execution functions do not retry.

```go
run, err := emergingthreats.RunConditionalCatalogThreats(ctx, client,
    model.RunConditionalRequest{
        Assets: []string{assetID},
        FilterBy: []model.Condition{
            {Name: "family", Value: []string{"example-family"}},
        },
    })
```

An empty ID list in a conditional request selects from the subscribed catalog;
the server applies its execution limit. A conditional run returns one grouped
`CampaignRun`. Ordinary bulk threat/campaign runs return slices. `RunCampaigns`
returns an empty slice or nil without error for a bodyless HTTP 204 response.

## Reports

| Function | Method and endpoint |
|---|---|
| `ListReports` | `GET /api/v2/emerging_threat/reports` |
| `GetReport` | `GET /api/v2/emerging_threat/reports/:id` |
| `DeleteReport` | `DELETE /api/v2/emerging_threat/reports/:id` |
| `ListCampaignReports` | `GET /api/v2/emerging_threat/campaign/reports` |
| `GetCampaignReport` | `GET /api/v2/emerging_threat/campaign/reports/:id` |
| `DeleteCampaignReport` | `DELETE /api/v2/emerging_threat/campaign/reports/:id` |

Reads require `emergingthreat.read`; deletes require `emergingthreat.delete`.
Detail, abort and delete functions take **run IDs**, not content IDs. Reports
cover catalog and authored runs. `AttackRun` includes step summaries, asset
details and scheduling identities. Scheduling identities retain the server's
`sql.NullString` JSON shape (`String`/`Valid`).

Errors wrap `*api.APIError`; use `errors.AsType[*api.APIError](err)` to inspect
status/details, or `errors.Is(err, api.ErrNotFound)` for missing resources.

## Streaming status

`WatchRun` reads `GET /api/v2/emerging_threat/runs/:run_id/sse` and returns an
`iter.Seq2[RunEvent, error]`. It closes the body when iteration ends or stops early.
There is no automatic reconnect. Configure a suitable HTTP client timeout for a
long-lived stream and cancel the context when finished.

```go
for event, err := range emergingthreats.WatchRun(ctx, client, threatRunID) {
    if err != nil {
        return err
    }
    switch event.Type {
    case "status-update":
        // Invalidation notification: refresh with GetReport.
    case "close":
        fmt.Println(event.Data) // completion string or server error object
    }
}
```

`WatchRun` applies to a per-threat run ID. For campaign progress, poll
`GetCampaignReport`; a conditional/grouped `CampaignRun.ID` is not a per-threat
stream ID.

## All execution groups

`executions.ListAllExecutions` calls `GET /api/v2/executions/all` and requires
`executions.read`. It returns `models.PaginationResponse[models.SimulationReport]`.
Unlike `executions.GetExecutions`, it includes playbooks, exposures, emerging
threats, MITRE and ad-hoc reports.

```go
reports, err := executions.ListAllExecutions(ctx, client,
    executions.ListAllExecutionsOpts{
        Size:                20,
        ExecutionGroupTypes: []string{"emerging_threat"},
        UseLink:             new(false),
        StartBlockedPercent: new(uint(0)),
    })
```

Use each row's `GroupType` to select its report API. A row's `RunID` is not
necessarily an individual execution ID. This listing is newest-first; no custom
order parameter is supported.
