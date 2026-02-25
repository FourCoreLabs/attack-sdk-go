package threatintel

import (
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

type IntelEdge struct {
	To    string `json:"to"`
	Label string `json:"label"`
}

type IntelNode struct {
	ID     string      `json:"id" yaml:"id"`
	Label  string      `json:"label" yaml:"label"`
	Icon   string      `json:"icon" yaml:"icon"`
	Threat string      `json:"threat" yaml:"threat"`
	Edges  []IntelEdge `json:"edges" yaml:"edges"`
}

type ChainActionInfo struct {
	Description string   `json:"description" yaml:"description"`
	Chains      []string `json:"chains" yaml:"chains"`
	Actions     []string `json:"actions" yaml:"actions"`
}

type IntelThreats struct {
	Email    *ChainActionInfo `json:"email" yaml:"email"`
	Network  *ChainActionInfo `json:"network" yaml:"network"`
	Endpoint *ChainActionInfo `json:"endpoint" yaml:"endpoint"`
	WAF      *ChainActionInfo `json:"waf" yaml:"waf"`
}

type ThreatIntel struct {
	ID         string       `json:"id" yaml:"id"`
	Name       string       `json:"name" yaml:"name"`
	Tags       models.Tag   `json:"tags" yaml:"tags"`
	Severity   string       `json:"severity" yaml:"severity"`
	Date       time.Time    `json:"date" yaml:"date"`
	Mitre      []string     `json:"mitre" yaml:"mitre"`
	AffectedOS []string     `json:"affected_os" yaml:"affected_os"`
	References []string     `json:"references" yaml:"references"`
	Threats    IntelThreats `json:"threats" yaml:"threats"`
	Graph      []IntelNode  `json:"graph" yaml:"graph"`

	// Content metadata
	Author   string `json:"author" yaml:"author"`
	Header   string `json:"header" yaml:"header"`
	Abstract string `json:"abstract" yaml:"abstract"`
}
