package chains

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// EndpointChainsV2URI is the base endpoint for the endpoint chains API
const EndpointChainsV2URI = "/api/v2/chains"

// ExecuteEndpointChain executes an endpoint attack chain by chain ID on specified assets
func ExecuteEndpointChain(ctx context.Context, h *api.HTTPAPI, chainID string, attackRun models.AttackRun) (models.GetExecutionResponse, error) {
	var response models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/%s/run", EndpointChainsV2URI, chainID)
	_, err := h.PostJSON(ctx, endpoint, attackRun, &response)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to execute endpoint chain: %w", err)
	}

	return response, nil
}
