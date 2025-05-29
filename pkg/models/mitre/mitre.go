package mitre

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
