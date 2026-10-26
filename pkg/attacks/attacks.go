package attacks

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

const AttacksV2URI = "/api/v2/attacks"

// CreateAttack creates an attack from the given actions and stagers.
func CreateAttack(ctx context.Context, h *api.HTTPAPI, wizard models.CreateAttackWizard) (models.Attack, error) {
	var resp models.Attack

	_, err := h.PostJSON(ctx, AttacksV2URI, wizard, &resp)
	if err != nil {
		return models.Attack{}, fmt.Errorf("failed to create attack: %w", err)
	}

	return resp, nil
}

// UpdateAttack edits a saved attack by ID.
func UpdateAttack(ctx context.Context, h *api.HTTPAPI, attackID int, wizard models.CreateAttackWizard) (models.SuccessIDResponse, error) {
	var resp models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%d", AttacksV2URI, attackID)
	_, err := h.PutJSON(ctx, endpoint, wizard, &resp)
	if err != nil {
		return models.SuccessIDResponse{}, fmt.Errorf("failed to update attack: %w", err)
	}

	return resp, nil
}

// DeleteAttack deletes a saved attack by ID.
func DeleteAttack(ctx context.Context, h *api.HTTPAPI, attackID int) (models.SuccessIDResponse, error) {
	var resp models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%d", AttacksV2URI, attackID)
	_, err := h.DeleteJSON(ctx, endpoint, nil, &resp)
	if err != nil {
		return models.SuccessIDResponse{}, fmt.Errorf("failed to delete attack: %w", err)
	}

	return resp, nil
}

// RunAttack runs a saved attack by ID on the given assets.
func RunAttack(ctx context.Context, h *api.HTTPAPI, attackID int, attackRun models.AttackRun) (models.GetExecutionResponse, error) {
	var resp models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/%d/run", AttacksV2URI, attackID)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &resp)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to run attack: %w", err)
	}

	return resp, nil
}
