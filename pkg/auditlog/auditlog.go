package auditlog

import (
	"strconv"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/auditlog"
)

var (
	AuditLogV2URI = "/api/v2/audit_logs"
)

type AuditLogOpts struct {
	Size   int    `json:"size"`
	Offset int    `json:"offset"`
	Order  string `json:"order"`
}

func GetAuditLogs(h *api.HTTPAPI, opts AuditLogOpts) (resp models.PaginationResponse[auditlog.AuditLog], err error) {
	_, err = h.GetJSON(AuditLogV2URI, &resp, api.ReqOptions{
		Params: map[string]string{
			"size":   strconv.FormatInt(int64(opts.Size), 10),
			"offset": strconv.FormatInt(int64(opts.Offset), 10),
			"order":  opts.Order,
		},
	})
	return resp, err
}
