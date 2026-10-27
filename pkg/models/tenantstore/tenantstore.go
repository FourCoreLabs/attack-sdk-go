// Package tenantstore defines tenant-store metadata and file response models.
package tenantstore

import (
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

// FileType identifies a tenant file's retention class.
type FileType string

// File retention classes. PermanentStore preserves the API's historical spelling.
const (
	Temporary      FileType = "temporary"
	PermanentStore FileType = "permanant_store"
	Artifact       FileType = "artifact"
)

// Metadata reports the organization's storage quotas and current usage in bytes.
// A quota of -1 means unlimited storage.
type Metadata struct {
	SoftTotalExternalFileSize    int64 `json:"soft_total_external_file_size"`
	HardTotalExternalFileSize    int64 `json:"hard_total_external_file_size"`
	CurrentTotalExternalFileSize int64 `json:"current_total_external_file_size"`
}

// File describes a tenant file. ObjectPath is its tenant:// URI, which can be
// used as the object payload when creating an emerging-threat campaign.
type File struct {
	ID             string     `json:"id"`
	UserID         uint       `json:"user_id"`
	OrgID          uint       `json:"org_id"`
	Type           FileType   `json:"attachment_type"`
	AttachmentName string     `json:"attachment_name"`
	ObjectPath     string     `json:"object_path"`
	MimeType       string     `json:"mime_type"`
	AttachmentSize int64      `json:"attachment_size"`
	Metadata       models.Tag `json:"metadata"`
	RelationCount  int        `json:"relation_count"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at"`
}
