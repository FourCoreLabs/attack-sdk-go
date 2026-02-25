package chains

import (
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
