package chains

import (
	"fmt"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	threatintel "github.com/fourcorelabs/attack-sdk-go/pkg/models/threat_intel"
)

type ChainStagerForUserState struct {
	StagerID   string `json:"stager_id"`
	StagerMode string `json:"stager_mode"`
}

type ChainStageForUserState struct {
	StageName    string   `yaml:"name" json:"name" db:"name"`
	StageID      string   `yaml:"id" json:"id" db:"id"`
	StageActions []string `yaml:"actions" json:"actions" db:"actions"`
	COF          bool     `yaml:"cof" json:"cof" db:"cof"`
	LM           bool     `yaml:"lm" json:"lm" db:"lm"`
}

type ChainC2 struct {
	C2Type    string `json:"c2_type" yaml:"c2_type"`
	C2Profile string `json:"c2_profile" yaml:"c2_profile"`
	ExfilOnly bool   `json:"exfil_only" yaml:"exfil_only"`
}

type ChainDisplay struct {
	Endpoint bool `json:"endpoint"`
	APT      bool `json:"apt"`
}

type ChainForUserState struct {
	AttackID    uint                      `json:"attack_id"`
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Platforms   []string                  `json:"platforms"`
	Elevated    bool                      `json:"elevated"`
	Tags        models.Tag                `json:"tags"`
	C2Profile   ChainC2                   `json:"c2"`
	Stagers     []ChainStagerForUserState `json:"stagers"`
	Stages      []ChainStageForUserState  `json:"stages"`
	Platform    string                    `json:"platform"`
	Malwares    []string                  `json:"malwares"`
	Display     ChainDisplay              `json:"display"`
	ReleaseDate time.Time                 `json:"release_date"`

	Success    int                           `json:"success_count"`
	Detected   int                           `json:"detected_count"`
	Total      int                           `json:"total_count"`
	LastRunAt  *time.Time                    `json:"last_run_at"`
	Exposures  []string                      `json:"exposures"`
	Techniques []models.MitreTacticTechnique `json:"techniques"`

	ThreatIntel []threatintel.ThreatIntel `json:"threat_intel"`
}

type ChainSummary struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Platforms      string `json:"platforms"`
	BlockedRate    string `json:"blocked_rate"`
	SuccessRate    string `json:"success_rate"`
	DetectionRate  string `json:"detection_rate"`
	ReleasedAt     string `json:"released_at"`
	LastExecutedAt string `json:"last_executed_at"`
}

type ChainExpanded ChainForUserState

func (c ChainExpanded) Summary() (any, error) {
	blockedRate := "0%"
	successRate := "0%"
	detectionRate := "0%"

	if c.Total > 0 {
		detectionRate = fmt.Sprintf("%.1f%%", float64(c.Detected*100)/float64(c.Total))
		successRate = fmt.Sprintf("%.1f%%", float64(c.Success*100)/float64(c.Total))
		blockedRate = fmt.Sprintf("%.1f%%", float64((c.Total-c.Success)*100)/float64(c.Total))
	}

	releasedAt := "N/A"
	if !c.ReleaseDate.IsZero() {
		releasedAt = c.ReleaseDate.Format(time.RFC3339)
	}

	lastExecutedAt := "N/A"
	if c.LastRunAt != nil && !c.LastRunAt.IsZero() {
		lastExecutedAt = c.LastRunAt.Format(time.RFC3339)
	}

	return ChainSummary{
		ID:             c.ID,
		Name:           c.Name,
		Platforms:      strings.Join(c.Platforms, ", "),
		BlockedRate:    blockedRate,
		SuccessRate:    successRate,
		DetectionRate:  detectionRate,
		ReleasedAt:     releasedAt,
		LastExecutedAt: lastExecutedAt,
	}, nil
}
