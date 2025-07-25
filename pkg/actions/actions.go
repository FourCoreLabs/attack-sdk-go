package actions

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// EndpointChainsV2URI is the base endpoint for the endpoint chains API
const EndpointActionsV2URI = "/api/v2/actions"

// ExecuteEndpointChain executes an endpoint attack chain by chain ID on specified assets
func ExecuteEndpointAction(ctx context.Context, h *api.HTTPAPI, attackRun models.AttackRunActionsStagers) (models.GetExecutionResponse, error) {
	var response models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/run", EndpointActionsV2URI)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &response)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to execute endpoint chain: %w", err)
	}

	return response, nil
}
