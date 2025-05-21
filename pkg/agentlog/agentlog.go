package agentlog

import (
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/agentlog"
)

// AgentLogV2URI is the endpoint for the agent logs API
const AgentLogV2URI = "/api/v2/agent_logs"

// AgentLogOpts represents options for listing agent logs
type AgentLogOpts struct {
	Size       int       `json:"size"`
	Offset     int       `json:"offset"`
	Order      string    `json:"order"`
	AssetIDs   []string  `json:"asset_id,omitempty"`
	Action     string    `json:"action,omitempty"`
	DateAfter  time.Time `json:"date_after,omitempty"`
	DateBefore time.Time `json:"date_before,omitempty"`
	Query      string    `json:"query,omitempty"`
}

// GetAgentLogs retrieves agent logs from the API with the given options
func GetAgentLogs(h *api.HTTPAPI, opts AgentLogOpts) (models.PaginationResponse[agentlog.AgentLog], error) {
	var resp models.PaginationResponse[agentlog.AgentLog]

	// Prepare parameters map
	params := map[string]string{
		"size":   strconv.FormatInt(int64(opts.Size), 10),
		"offset": strconv.FormatInt(int64(opts.Offset), 10),
		"order":  opts.Order,
	}

	// Add optional filter params if set
	if opts.Action != "" {
		params["action"] = opts.Action
	}

	if !opts.DateAfter.IsZero() {
		params["date_after"] = opts.DateAfter.Format(time.RFC3339)
	}

	if !opts.DateBefore.IsZero() {
		params["date_before"] = opts.DateBefore.Format(time.RFC3339)
	}

	if opts.Query != "" {
		params["q"] = opts.Query
	}

	// Add asset_id if there are any in the list
	if len(opts.AssetIDs) > 0 {
		params["asset_id"] = strings.Join(opts.AssetIDs, ",")
	}

	// Make the API request
	_, err := h.GetJSON(AgentLogV2URI, &resp, api.ReqOptions{
		Params: params,
	})

	return resp, err
}
