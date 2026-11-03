package executions

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/internal/query"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// AllExecutionsV2URI lists reports across all supported execution group types.
const AllExecutionsV2URI = ExecutionsV2URI + "/all"

// ListAllExecutionsOpts selects combined simulation, playbook, emerging-threat,
// exposure, MITRE and ad-hoc reports. It is not the individual-execution listing.
// All filters use filter[...] query keys. Dates use RFC3339; nil booleans and
// percentage pointers omit a filter, while pointers to zero/false are explicit.
// The server sorts this combined listing newest first; it has no order option.
type ListAllExecutionsOpts struct {
	Size                int
	Offset              int
	Name                string
	DateAfter           time.Time
	DateBefore          time.Time
	AssetIDs            []string
	UserIDs             []uint
	ActionIDs           []string
	ScheduleIDs         []string
	ExecutionTypes      []string
	ExecutionGroupTypes []string
	UseLink             *bool
	UseAttachment       *bool
	Success             *bool
	AssetCount          *uint64
	models.PercentageFilter
}

// ListAllExecutions retrieves the unified reports page, including emerging-threat
// runs. Requires executions.read. GroupType determines which report detail API
// accepts the row's RunID; do not pass every RunID to GetExecutionReport.
func ListAllExecutions(ctx context.Context, h *api.HTTPAPI, opts ListAllExecutionsOpts) (models.PaginationResponse[models.SimulationReport], error) {
	var result models.PaginationResponse[models.SimulationReport]
	params := make(url.Values)
	if err := query.Pagination(params, models.PaginationOpts{Size: opts.Size, Offset: opts.Offset}); err != nil {
		return result, err
	}
	if err := query.Percentages(params, opts.PercentageFilter); err != nil {
		return result, err
	}
	if opts.Name != "" {
		params.Set("filter[name]", opts.Name)
	}
	query.Time(params, "date_after", opts.DateAfter)
	query.Time(params, "date_before", opts.DateBefore)
	query.Bool(params, "use_link", opts.UseLink)
	query.Bool(params, "use_attachment", opts.UseAttachment)
	query.Bool(params, "success", opts.Success)
	if opts.AssetCount != nil {
		if *opts.AssetCount == 0 {
			return result, errors.New("asset count must be positive")
		}
		params.Set("filter[asset_count]", strconv.FormatUint(*opts.AssetCount, 10))
	}
	for key, values := range map[string][]string{
		"asset_id": opts.AssetIDs, "action_id": opts.ActionIDs, "schedule_id": opts.ScheduleIDs,
		"execution_type": opts.ExecutionTypes, "execution_group_type": opts.ExecutionGroupTypes,
	} {
		query.Strings(params, key, values)
	}
	if len(opts.UserIDs) > 0 {
		values := make([]string, len(opts.UserIDs))
		for i, id := range opts.UserIDs {
			values[i] = strconv.FormatUint(uint64(id), 10)
		}
		params.Set("filter[user_id]", strings.Join(values, ","))
	}
	_, err := h.GetJSON(ctx, AllExecutionsV2URI, &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list all execution reports: %w", err)
	}
	return result, nil
}
