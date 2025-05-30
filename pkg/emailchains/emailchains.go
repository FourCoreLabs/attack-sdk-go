package emailchains

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// EmailChainsV2URI is the base endpoint for the email chains API
const EmailChainsV2URI = "/api/v2/email/chain"

// ExecuteEmailChain executes an email attack chain by chain ID on specified assets
func ExecuteEmailChain(ctx context.Context, h *api.HTTPAPI, chainID string, attackRun models.AttackRun) (models.AttackExecution, error) {
	var response models.AttackExecution

	endpoint := fmt.Sprintf("%s/%s/run", EmailChainsV2URI, chainID)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &response)
	if err != nil {
		return models.AttackExecution{}, fmt.Errorf("failed to execute email chain: %w", err)
	}

	return response, nil
}
