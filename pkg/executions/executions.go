package executions

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// ExecutionsV2URI is the endpoint for the executions API
const ExecutionsV2URI = "/api/v2/executions"

// ExecutionOpts represents options for listing executions
type ExecutionOpts struct {
	Size          int       `json:"size"`
	Offset        int       `json:"offset"`
	Order         string    `json:"order"`
	Name          string    `json:"name,omitempty"`
	DateBefore    time.Time `json:"date_before,omitempty"`
	DateAfter     time.Time `json:"date_after,omitempty"`
	AssetIDs      []string  `json:"asset_id,omitempty"`
	Hostnames     []string  `json:"hostname,omitempty"`
	ChainIDs      []string  `json:"chain_id,omitempty"`
	AttackIDs     []string  `json:"attack_id,omitempty"`
	ExecutionType []string  `json:"execution_type,omitempty"`
	Status        string    `json:"status,omitempty"`
}

// GetExecutions retrieves executions from the API with the given options
func GetExecutions(h *api.HTTPAPI, opts ExecutionOpts) (models.ListWithCountExecutions, error) {
	var resp models.ListWithCountExecutions

	// Prepare parameters map
	params := map[string]string{
		"size":   strconv.FormatInt(int64(opts.Size), 10),
		"offset": strconv.FormatInt(int64(opts.Offset), 10),
		"order":  opts.Order,
	}

	// Add optional filter params if set
	if opts.Name != "" {
		params["name"] = opts.Name
	}

	if !opts.DateBefore.IsZero() {
		params["date_before"] = opts.DateBefore.Format(time.RFC3339)
	}

	if !opts.DateAfter.IsZero() {
		params["date_after"] = opts.DateAfter.Format(time.RFC3339)
	}

	if opts.Status != "" {
		params["status"] = opts.Status
	}

	// Add array parameters
	if len(opts.AssetIDs) > 0 {
		params["asset_id"] = strings.Join(opts.AssetIDs, ",")
	}

	if len(opts.Hostnames) > 0 {
		params["hostname"] = strings.Join(opts.Hostnames, ",")
	}

	if len(opts.ChainIDs) > 0 {
		params["chain_id"] = strings.Join(opts.ChainIDs, ",")
	}

	if len(opts.AttackIDs) > 0 {
		params["attack_id"] = strings.Join(opts.AttackIDs, ",")
	}

	if len(opts.ExecutionType) > 0 {
		params["execution_type"] = strings.Join(opts.ExecutionType, ",")
	}

	// Make the API request
	_, err := h.GetJSON(ExecutionsV2URI, &resp, api.ReqOptions{
		Params: params,
	})

	return resp, err
}

// GetExecutionReport retrieves a detailed execution report by ID
func GetExecutionReport(h *api.HTTPAPI, executionID string) (models.GetExecutionResponse, error) {
	var resp models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/%s/report", ExecutionsV2URI, executionID)
	_, err := h.GetJSON(endpoint, &resp)

	return resp, err
}

// DeleteExecution deletes an execution by ID
func DeleteExecution(h *api.HTTPAPI, executionID string) (models.SuccessIDResponse, error) {
	var resp models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s", ExecutionsV2URI, executionID)
	_, err := h.DeleteJSON(endpoint, nil, &resp)

	return resp, err
}
