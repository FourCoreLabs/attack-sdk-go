package mitre

import "fmt"

// MitreTacticTechniqueWithActionAndStagers represents MITRE ATT&CK technique information with associated actions and stagers
type MitreTacticTechniqueWithActionAndStagers struct {
	AbsoluteID       string   `json:"absolute_id"`
	Actions          []string `json:"actions"`
	Detected         int64    `json:"detected"`
	Stagers          []string `json:"stagers"`
	StepID           int      `json:"step_id"`
	SubTechniqueID   string   `json:"sub_technique_id"`
	Success          int64    `json:"success"`
	TacticID         string   `json:"tactic_id"`
	Tactics          []string `json:"tactics"`
	TechniqueID      string   `json:"technique_id"`
	Total            int64    `json:"total"`
	UniqueActionsRun []string `json:"unique_actions_run"`
	UniqueStageRuns  []string `json:"unique_stagers_run"`
}

type CoverageSummary struct {
	TechniqueID  string `json:"technique_id"`
	TacticID     string `json:"tactic_id"`
	SubTechnique string `json:"sub_technique"`
	Total        string `json:"total"`
	Success      string `json:"success"`
	Detected     string `json:"detected"`
	Actions      string `json:"actions"`
	Stagers      string `json:"stagers"`
}

type CoverageExpanded MitreTacticTechniqueWithActionAndStagers

func (m CoverageExpanded) Summary() (any, error) {
	successRate := "0%"
	detectionRate := "0%"
	if m.Total > 0 {
		successRate = fmt.Sprintf("%.1f%%", float64(m.Success)/float64(m.Total)*100)
		detectionRate = fmt.Sprintf("%.1f%%", float64(m.Detected)/float64(m.Total)*100)
	}

	techniqueID := m.TechniqueID
	if m.SubTechniqueID != "" {
		techniqueID = fmt.Sprintf("%s.%s", m.TechniqueID, m.SubTechniqueID)
	}

	return CoverageSummary{
		TechniqueID:  techniqueID,
		TacticID:     m.TacticID,
		SubTechnique: m.SubTechniqueID,
		Total:        fmt.Sprintf("%d", m.Total),
		Success:      successRate,
		Detected:     detectionRate,
		Actions:      fmt.Sprintf("%d", len(m.Actions)),
		Stagers:      fmt.Sprintf("%d", len(m.Stagers)),
	}, nil
}
