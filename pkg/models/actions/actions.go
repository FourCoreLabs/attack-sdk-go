package actions

import (
	"strings"
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
	Rules        []models.Rule                 `json:"rules"`
	Conditions   []string                      `json:"conditions"`
	Tags         models.Tag                    `json:"tags"`
}

type ActionSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Platforms  string `json:"platforms"`
	ReleasedAt string `json:"released_at"`
}

type ActionExpanded ActionForUserState

func (a ActionExpanded) Summary() (any, error) {
	releasedAt := "N/A"
	if !a.ReleaseDate.IsZero() {
		releasedAt = a.ReleaseDate.Format(time.RFC3339)
	}

	platforms := make([]string, 0, len(a.Platforms))
	for _, platform := range a.Platforms {
		platforms = append(platforms, platform)
	}

	return ActionSummary{
		ID:         a.ID,
		Name:       a.Name,
		Severity:   a.Severity,
		Platforms:  strings.Join(platforms, ", "),
		ReleasedAt: releasedAt,
	}, nil
}
