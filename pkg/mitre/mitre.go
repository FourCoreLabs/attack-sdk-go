package mitre

import (
	"context"
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/mitre"
)

// MitreV2URI is the base endpoint for the MITRE ATT&CK API
const MitreV2URI = "/api/v2/mitre"

// GetAllMitreCoverage retrieves complete MITRE ATT&CK coverage information for the user
func GetAllMitreCoverage(ctx context.Context, h *api.HTTPAPI, days int) ([]mitre.MitreTacticTechniqueWithActionAndStagers, error) {
	var resp []mitre.MitreTacticTechniqueWithActionAndStagers

	endpoint := fmt.Sprintf("%s/all", MitreV2URI)
	params := map[string]string{
		"d": fmt.Sprintf("%d", days),
	}

	_, err := h.GetJSON(ctx, endpoint, &resp, api.ReqOptions{
		Params: params,
	})

	return resp, err
}

// GetMitreTechnique retrieves MITRE ATT&CK technique information based on technique_id
func GetMitreTechnique(ctx context.Context, h *api.HTTPAPI, techniqueID string, days int) (mitre.MitreTacticTechniqueWithActionAndStagers, error) {
	var resp mitre.MitreTacticTechniqueWithActionAndStagers

	endpoint := fmt.Sprintf("%s/%s", MitreV2URI, techniqueID)
	params := map[string]string{
		"d": fmt.Sprintf("%d", days),
	}

	_, err := h.GetJSON(ctx, endpoint, &resp, api.ReqOptions{
		Params: params,
	})

	return resp, err
}
