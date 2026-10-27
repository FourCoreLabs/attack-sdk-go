# attack-sdk-go

SDK and CLI for FourCore ATTACK REST API

## Overview

**attack-sdk-go** provides both a Go SDK and a CLI tool to interact with the [FourCore ATTACK REST API](https://fourcore.io). It enables management and retrieval of resources such as assets, agent logs, and audit logs.

---

## Features

- **CLI Tool**: Manage assets, agent logs, audit logs, and configuration from the command line.
- **Go SDK**: Programmatic access to FourCore API endpoints.
- **Configurable**: Supports configuration via file, environment variables, and command-line flags.
- **Pagination, Filtering, and Formatting**: Flexible output and query options for logs and assets.

---

## Installation

### Prerequisites

- Go 1.27.3 or higher

### Build CLI

```sh
git clone https://github.com/fourcorelabs/attack-sdk-go.git
cd attack-sdk-go/cmd/cli
go build -o fourcore-cli
```

---

## Usage

### CLI

Run the CLI:

```sh
./fourcore-cli [command] [flags]
```

#### Global Flags

- `--api-key, -k`    API Key for authentication (can also use `FOURCORE_API_KEY` env var)
- `--base-url, -u`   Base URL for the API (can also use `FOURCORE_BASE_URL` env var)

#### Commands

- `asset` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Manage assets (list, get, enable, disable, delete, tags, analytics, attacks, executions, packs)
- `agent log` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;List agent logs with filtering and formatting options
- `audit` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;List audit logs
- `config` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;View and set CLI configuration

#### Example: List Assets

```sh
./fourcore-cli asset list --format table
```

#### Example: Get Agent Logs

```sh
./fourcore-cli agent log list --size 20 --order ASC --format json
```

#### Example: Set API Key

```sh
./fourcore-cli config set api-key <your-api-key>
```

#### Example: View Current Config

```sh
./fourcore-cli config view
```

---

## Configuration

Configuration is stored in a JSON file at:

- **Linux/macOS**: `~/.fourcore/config.json`
- **Windows**: `%USERPROFILE%\.fourcore\config.json`

You can set values using the CLI:

```sh
./fourcore-cli config set api-key <your-api-key>
./fourcore-cli config set base-url https://prod.fourcore.io
```

Or by setting environment variables:

- `FOURCORE_API_KEY`
- `FOURCORE_BASE_URL`

---

## Go SDK Usage

Import the SDK in your Go project:

```go
import "github.com/fourcorelabs/attack-sdk-go/pkg/api"
import "github.com/fourcorelabs/attack-sdk-go/pkg/asset"
```

### Example: List Assets

```go
baseURL := os.Getenv("FOURCOREBASEURL")
client, err := api.NewHTTPAPI(baseURL, "<your-api-key>")
if err != nil {
    return err
}
assets, err := asset.GetAssets(context.Background(), client)
```

### Emerging-Threat Campaigns and Tenant Files (API v2)

The SDK provides these packages:

| Package | Functions |
| --- | --- |
| `pkg/emergingthreats` | `CreateCampaign`, `UpdateCampaign`, `DeleteCampaign`, `ListCampaigns`, `GetCampaign`, `GetCampaignFilters` |
| `pkg/tenantstore` | `GetMetadata`, `UploadFile`, `ListFiles`, `GetDownloadURL`, `DownloadFile`, `DeleteFile` |
| `pkg/models/emergingthreats` | Typed campaign, IOC entry, request, filter, and analytics models |
| `pkg/models/tenantstore` | Typed file and storage metadata models |

Campaign calls require the corresponding `useremergingthreats.create/read/update/delete`
API-key permissions and the `user_emerging_threats` feature. Tenant-store calls require
`tenant_store.create/read/download/delete` permissions and the `tenant_store` feature.
Listing a file does not grant download permission.

#### Upload a sample and create a campaign

```go
import (
    "context"
    "os"

    "github.com/fourcorelabs/attack-sdk-go/pkg/api"
    "github.com/fourcorelabs/attack-sdk-go/pkg/emergingthreats"
    campaignmodel "github.com/fourcorelabs/attack-sdk-go/pkg/models/emergingthreats"
    "github.com/fourcorelabs/attack-sdk-go/pkg/tenantstore"
)

func createSampleCampaign(ctx context.Context, client *api.HTTPAPI, path string) (campaignmodel.Campaign, error) {
    file, err := os.Open(path)
    if err != nil {
        return campaignmodel.Campaign{}, err
    }
    defer file.Close()
    info, err := file.Stat()
    if err != nil {
        return campaignmodel.Campaign{}, err
    }
    uploaded, err := tenantstore.UploadFile(ctx, client, file, tenantstore.UploadFileOpts{
        Size: info.Size(), AttachmentName: info.Name(),
    })
    if err != nil {
        return campaignmodel.Campaign{}, err
    }
    return emergingthreats.CreateCampaign(ctx, client, campaignmodel.CampaignCreateRequest{
        Name: "Sample campaign",
        EmergingThreats: []campaignmodel.AttackInput{{
            Name: info.Name(),
            PayloadType: campaignmodel.PayloadTypeObject,
            Payload: campaignmodel.Payload{Object: uploaded.ObjectPath},
        }},
    })
}
```

Uploads use raw `application/octet-stream` bytes, not multipart or base64. Supply
the exact size. The SDK streams uploads, does not retry/replay them on redirects,
and leaves ownership of the source reader with the caller.

#### Filters and optional cleanup

```go
campaigns, err := emergingthreats.ListCampaigns(ctx, client, emergingthreats.ListCampaignsOpts{
    Size: 20,
    Order: "-updated_at,name",
    Family: []string{"family-a", "family-b"},
    Days: new(uint(30)),
    UseLink: new(false),
})

// A nil delete request uses the server's default cleanup behavior.
// A pointer to false explicitly preserves orphaned tenant files.
deleted, err := emergingthreats.DeleteCampaign(ctx, client, "<campaign-id>", &campaignmodel.CampaignDeleteRequest{
    DeleteTenantFileOnNoRelation: new(false),
})
```

Zero-value list options use server pagination defaults. Filters are encoded in
the API's `filter[name]=value1,value2` form. Analytics options support `Days`, or
paired `StartDayRange`/`EndDayRange` timestamps. Nil boolean pointers omit a filter;
`new(false)` sends an explicit false value. Requests use `references`, while
campaign responses expose `Reference` (`reference` on the wire).

#### Stream a download

```go
body, err := tenantstore.DownloadFile(ctx, client, "<file-id>")
if err != nil {
    return err
}
defer body.Close()
_, err = io.Copy(destination, body)
```

`GetDownloadURL` resolves the API's HTTP 307 without fetching bytes. `DownloadFile`
then opens the presigned URL without sending the API key or cookies, even when
the object store shares the API host. Downloads remain streamed; callers must
close the reader. Presigned URLs are temporary credentials: do not log them.

API failures support `errors.As` with `*api.APIError` for status/title/detail and
`errors.Is` with the existing authentication, not-found, and rate-limit sentinels.

---

## Development

- Main CLI entrypoint: [cmd/cli/main.go](cmd/cli/main.go)
- CLI commands: [cmd/cli/cmd/](cmd/cli/cmd/)
- SDK packages: [pkg/](pkg/)
- Configuration: [pkg/config/config.go](pkg/config/config.go)

---

## License

See [LICENSE.md](LICENSE.md).

---

## Contributing

Pull requests and issues are welcome!

---

## Support

For support, contact [FourCore Labs](https://fourcore.io).
