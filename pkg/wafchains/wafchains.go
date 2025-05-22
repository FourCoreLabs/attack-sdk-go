package wafchains

import (
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// WAFChainsV2URI is the base endpoint for the WAF chains API
const WAFChainsV2URI = "/api/v2/waf/chain"

// ExecuteWAFChain executes a WAF attack chain by chain ID on specified assets
func ExecuteWAFChain(h *api.HTTPAPI, chainID string, attackRun models.AttackRun) (models.GetExecutionResponse, error) {
	var response models.GetExecutionResponse

	endpoint := fmt.Sprintf("%s/%s/run", WAFChainsV2URI, chainID)
	_, err := h.PostJSON(endpoint, attackRun, &response)
	if err != nil {
		return models.GetExecutionResponse{}, fmt.Errorf("failed to execute WAF chain: %w", err)
	}

	return response, nil
}
