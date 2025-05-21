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

- Go 1.18 or higher

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
assets, err := asset.GetAssets(client)
```

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