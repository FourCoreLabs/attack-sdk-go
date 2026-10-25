package attacks

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// AttacksV1URI is the endpoint for creating saved custom attacks.
const AttacksV1URI = "/api/v1/attacks"

// CreateAttack creates (saves) an attack from the given actions and stagers.
func CreateAttack(ctx context.Context, h *api.HTTPAPI, wizard models.CreateAttackWizard) (models.Attack, error) {
	var resp models.Attack

	_, err := h.PostJSON(ctx, AttacksV1URI, wizard, &resp)
	if err != nil {
		return models.Attack{}, fmt.Errorf("failed to create attack: %w", err)
	}

	return resp, nil
}
