package actions

import (
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

type ActionStepForUserState struct {
	Description string `json:"description"`
}

type ActionInfoForUserState struct {
	Steps []ActionStepForUserState `json:"steps"`
}

type ActionDisplay struct {
	Endpoint bool `json:"endpoint,omitempty"`
	APT      bool `json:"apt,omitempty"`
}

type ActionForUserState struct {
	ID           string                        `json:"id"`
	Key          string                        `json:"key"`
	Name         string                        `json:"name"`
	ReleaseDate  time.Time                     `json:"release_date"`
	Description  string                        `json:"description"`
	Severity     string                        `json:"severity"`
	Exposures    []string                      `json:"exposures"`
	Platforms    []string                      `json:"platforms"`
	Info         ActionInfoForUserState        `json:"info"`
	Type         string                        `json:"type"`
	Display      ActionDisplay                 `json:"display"`
	MitreTactics []models.MitreTacticTechnique `json:"mitre"`
	Rules        models.Rule                   `json:"rules"`
	Conditions   []string                      `json:"conditions"`
	Tags         models.Tag                    `json:"tags"`
}
