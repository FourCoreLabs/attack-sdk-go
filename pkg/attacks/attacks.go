package attacks

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	chainsmodel "github.com/fourcorelabs/attack-sdk-go/pkg/models/chains"
)

const (
	AttacksV1URI        = "/api/v1/attacks"
	AttacksContentV1URI = "/api/v1/content/attacks"

	listPageSize = 100
)

// CreateAttack creates (saves) an attack from the given actions and stagers.
func CreateAttack(ctx context.Context, h *api.HTTPAPI, wizard models.CreateAttackWizard) (models.Attack, error) {
	var resp models.Attack

	_, err := h.PostJSON(ctx, AttacksV1URI, wizard, &resp)
	if err != nil {
		return models.Attack{}, fmt.Errorf("failed to create attack: %w", err)
	}

	return resp, nil
}

// RunAttack runs a saved attack by ID on the given assets.
func RunAttack(ctx context.Context, h *api.HTTPAPI, attackID int, attackRun models.AttackRun) (models.GetExecutionResponse, error) {
	var resp models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/%d/run", AttacksV1URI, attackID)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &resp)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to run attack: %w", err)
	}

	return resp, nil
}

// GetAttack fetches a single saved attack by ID.
func GetAttack(ctx context.Context, h *api.HTTPAPI, attackID int) (chainsmodel.ChainForUserState, error) {
	var resp chainsmodel.ChainForUserState

	endpoint := fmt.Sprintf("%s/%d", AttacksContentV1URI, attackID)
	_, err := h.GetJSON(ctx, endpoint, &resp)
	if err != nil {
		return chainsmodel.ChainForUserState{}, fmt.Errorf("failed to fetch attack: %w", err)
	}

	return resp, nil
}

// UpdateAttack edits a saved attack by ID.
func UpdateAttack(ctx context.Context, h *api.HTTPAPI, attackID int, wizard models.CreateAttackWizard) (models.SuccessIDResponse, error) {
	var resp models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%d", AttacksV1URI, attackID)
	_, err := h.PutJSON(ctx, endpoint, wizard, &resp)
	if err != nil {
		return models.SuccessIDResponse{}, fmt.Errorf("failed to update attack: %w", err)
	}

	return resp, nil
}

// DeleteAttack deletes a saved attack by ID.
func DeleteAttack(ctx context.Context, h *api.HTTPAPI, attackID int) error {
	var discard any // server returns {"success":"...string..."}, not models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%d", AttacksV1URI, attackID)
	_, err := h.DeleteJSON(ctx, endpoint, nil, &discard)
	if err != nil {
		return fmt.Errorf("failed to delete attack: %w", err)
	}

	return nil
}

// AttackListItem is one entry of the paginated attacks listing.
type AttackListItem struct {
	Type string                        `json:"type"`
	Data chainsmodel.ChainForUserState `json:"data"`
}

type ListAttackOpts struct {
	Size        int      `json:"size"`
	Offset      int      `json:"offset"`
	Order       []string `json:"order"`
	Name        string   `json:"name,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	RunElevated *bool    `json:"run_elevated,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Stagers     []string `json:"stagers,omitempty"`
}

// ListAttacks lists saved attacks.
func ListAttacks(ctx context.Context, h *api.HTTPAPI, opts ListAttackOpts) (models.PaginationResponse[AttackListItem], error) {
	if len(opts.Actions) == 0 && len(opts.Stagers) == 0 {
		return fetchAttacks(ctx, h, opts.Offset, opts.Size, opts)
	}

	var all []AttackListItem
	for offset := 0; ; offset += listPageSize {
		page, err := fetchAttacks(ctx, h, offset, listPageSize, opts)
		if err != nil {
			return models.PaginationResponse[AttackListItem]{}, err
		}

		all = append(all, page.Data...)
		if len(page.Data) == 0 || len(all) >= page.TotalRows {
			break
		}
	}

	filtered := make([]AttackListItem, 0, len(all))
	for _, item := range all {
		if matchesFilter(item, opts.Actions, opts.Stagers) {
			filtered = append(filtered, item)
		}
	}

	return models.PaginationResponse[AttackListItem]{
		TotalRows: len(filtered),
		Data:      filtered,
	}, nil
}

func fetchAttacks(ctx context.Context, h *api.HTTPAPI, offset, size int, opts ListAttackOpts) (models.PaginationResponse[AttackListItem], error) {
	var resp models.PaginationResponse[AttackListItem]

	params := url.Values{
		"size":   []string{strconv.FormatInt(int64(size), 10)},
		"offset": []string{strconv.FormatInt(int64(offset), 10)},
		"order":  opts.Order,
	}

	if opts.Name != "" {
		params.Add("filter[name]", opts.Name)
	}

	if len(opts.Platforms) > 0 {
		params["filter[platforms]"] = opts.Platforms
	}

	if opts.RunElevated != nil {
		params.Add("filter[run_elevated]", strconv.FormatBool(*opts.RunElevated))
	}

	_, err := h.GetJSON(ctx, AttacksContentV1URI, &resp, api.ReqOptions{Params: params})
	if err != nil {
		return models.PaginationResponse[AttackListItem]{}, fmt.Errorf("failed to list attacks: %w", err)
	}

	return resp, nil
}

func matchesFilter(item AttackListItem, actions, stagers []string) bool {
	if len(actions) > 0 {
		hit := false
		for _, stage := range item.Data.Stages {
			if slices.ContainsFunc(stage.StageActions, func(a string) bool { return slices.Contains(actions, a) }) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}

	if len(stagers) > 0 {
		hit := slices.ContainsFunc(item.Data.Stagers, func(s chainsmodel.ChainStagerForUserState) bool {
			return slices.Contains(stagers, s.StagerID)
		})
		if !hit {
			return false
		}
	}

	return true
}
