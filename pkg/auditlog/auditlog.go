package auditlog

import (
	"context"
	"strconv"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/auditlog"
)

// AuditLogV2URI is the endpoint for the audit logs API.
const AuditLogV2URI = "/api/v2/audit_logs"

// AuditLogOpts represents options for listing audit logs.
type AuditLogOpts struct {
	Size   int    `json:"size"`
	Offset int    `json:"offset"`
	Order  string `json:"order"`
}

// GetAuditLogs retrieves audit logs from the API with the given options.
func GetAuditLogs(ctx context.Context, h *api.HTTPAPI, opts AuditLogOpts) (models.PaginationResponse[auditlog.AuditLog], error) {
	var resp models.PaginationResponse[auditlog.AuditLog]

	_, err := h.GetJSON(ctx, AuditLogV2URI, &resp, api.ReqOptions{
		Params: map[string]string{
			"size":   strconv.FormatInt(int64(opts.Size), 10),
			"offset": strconv.FormatInt(int64(opts.Offset), 10),
			"order":  opts.Order,
		},
	})

	return resp, err
}
