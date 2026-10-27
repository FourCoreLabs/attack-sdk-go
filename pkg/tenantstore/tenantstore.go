// Package tenantstore manages tenant files through the v2 API.
package tenantstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	model "github.com/fourcorelabs/attack-sdk-go/pkg/models/tenantstore"
)

// TenantStoreV2URI is the tenant-store API base path.
const TenantStoreV2URI = "/api/v2/tenant_store"

// UploadFileOpts describes a raw binary upload. Size must be positive and match
// the number of bytes to upload. Uploads are not retried or replayed on redirects.
type UploadFileOpts struct {
	Size           int64
	AttachmentName string
}

// ListFilesOpts controls file pagination, ordering, and filtering.
// Nil size bounds omit the bound; a pointer to zero explicitly filters zero bytes.
// Size zero uses the server default. Order uses comma-separated sort fields.
type ListFilesOpts struct {
	Size           int
	Offset         int
	Order          string
	Name           string
	MimeType       []string
	AttachmentName []string
	Type           []model.FileType
	StartFileSize  *uint64
	EndFileSize    *uint64
}

// GetMetadata retrieves the organization's storage limits and usage.
func GetMetadata(ctx context.Context, h *api.HTTPAPI) (model.Metadata, error) {
	var result model.Metadata
	_, err := h.GetJSON(ctx, TenantStoreV2URI+"/metadata", &result)
	if err != nil {
		return result, fmt.Errorf("get tenant-store metadata: %w", err)
	}
	return result, nil
}

// UploadFile streams Size bytes from body into a temporary tenant file.
// The caller owns body and remains responsible for closing it if necessary.
func UploadFile(ctx context.Context, h *api.HTTPAPI, body io.Reader, opts UploadFileOpts) (model.File, error) {
	if body == nil || opts.Size <= 0 {
		return model.File{}, errors.New("upload requires a reader and a positive file size")
	}
	response, err := h.Do(ctx, http.MethodPost, TenantStoreV2URI+"/upload_file", io.LimitReader(body, opts.Size), api.ReqOptions{
		Params: url.Values{
			"size":            {strconv.FormatInt(opts.Size, 10)},
			"attachment_name": {opts.AttachmentName},
		},
		Headers:       url.Values{"Content-Type": {"application/octet-stream"}, "Accept": {"application/json"}},
		ContentLength: opts.Size,
		NoRedirect:    true,
	})
	if err != nil {
		return model.File{}, fmt.Errorf("upload tenant file: %w", err)
	}
	var result model.File
	if err := api.DecodeResponse(response, &result); err != nil {
		return model.File{}, fmt.Errorf("upload tenant file: %w", err)
	}
	return result, nil
}

// ListFiles lists files owned by the API key's organization.
func ListFiles(ctx context.Context, h *api.HTTPAPI, opts ListFilesOpts) (models.PaginationResponse[model.File], error) {
	var result models.PaginationResponse[model.File]
	if opts.Size < 0 || opts.Offset < 0 {
		return result, errors.New("file size and offset must not be negative")
	}
	params := make(url.Values)
	if opts.Size > 0 {
		params.Set("size", strconv.Itoa(opts.Size))
	}
	if opts.Offset > 0 {
		params.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.Order != "" {
		params.Set("order", opts.Order)
	}
	if opts.Name != "" {
		params.Set("filter[name]", opts.Name)
	}
	if len(opts.MimeType) > 0 {
		params.Set("filter[mime_type]", strings.Join(opts.MimeType, ","))
	}
	if len(opts.AttachmentName) > 0 {
		params.Set("filter[attachment_name]", strings.Join(opts.AttachmentName, ","))
	}
	if len(opts.Type) > 0 {
		types := make([]string, 0, len(opts.Type))
		for _, value := range opts.Type {
			types = append(types, string(value))
		}
		params.Set("filter[type]", strings.Join(types, ","))
	}
	if opts.StartFileSize != nil {
		params.Set("filter[start_file_size]", strconv.FormatUint(*opts.StartFileSize, 10))
	}
	if opts.EndFileSize != nil {
		params.Set("filter[end_file_size]", strconv.FormatUint(*opts.EndFileSize, 10))
	}
	_, err := h.GetJSON(ctx, TenantStoreV2URI+"/files", &result, api.ReqOptions{Params: params})
	if err != nil {
		return result, fmt.Errorf("list tenant files: %w", err)
	}
	return result, nil
}

// GetDownloadURL resolves the API's 307 response without fetching file bytes.
// The returned presigned URL is short-lived and must not be logged or persisted.
func GetDownloadURL(ctx context.Context, h *api.HTTPAPI, id string) (*url.URL, error) {
	endpoint, err := fileEndpoint(id)
	if err != nil {
		return nil, err
	}
	response, err := h.Do(ctx, http.MethodGet, endpoint+"/download", nil, api.ReqOptions{NoRedirect: true})
	if err != nil {
		return nil, fmt.Errorf("get tenant file download URL: %w", err)
	}
	if response.StatusCode != http.StatusTemporaryRedirect {
		if err := api.DecodeResponse(response, nil); err != nil {
			return nil, fmt.Errorf("get tenant file download URL: %w", err)
		}
		return nil, fmt.Errorf("expected download redirect, got HTTP %d", response.StatusCode)
	}
	defer response.Body.Close()
	location, err := response.Location()
	if err != nil {
		return nil, fmt.Errorf("read tenant file download location: %w", err)
	}
	if (location.Scheme != "http" && location.Scheme != "https") || location.Host == "" || location.User != nil {
		return nil, errors.New("invalid tenant file download URL")
	}
	return location, nil
}

// DownloadFile opens a file stream using its presigned URL without forwarding
// the API key or cookies. The caller must close the returned reader.
func DownloadFile(ctx context.Context, h *api.HTTPAPI, id string) (io.ReadCloser, error) {
	location, err := GetDownloadURL(ctx, h, id)
	if err != nil {
		return nil, err
	}
	response, err := h.GetStream(ctx, location.String())
	if err != nil {
		return nil, fmt.Errorf("download tenant file: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		if err := api.DecodeResponse(response, nil); err != nil {
			return nil, fmt.Errorf("download tenant file: %w", err)
		}
		return nil, fmt.Errorf("unexpected download HTTP status %d", response.StatusCode)
	}
	return response.Body, nil
}

// DeleteFile removes a file owned by the API key's organization.
func DeleteFile(ctx context.Context, h *api.HTTPAPI, id string) (models.SuccessIDResponse, error) {
	endpoint, err := fileEndpoint(id)
	if err != nil {
		return models.SuccessIDResponse{}, err
	}
	var result models.SuccessIDResponse
	_, err = h.DeleteJSON(ctx, endpoint, nil, &result)
	if err != nil {
		return result, fmt.Errorf("delete tenant file: %w", err)
	}
	return result, nil
}

func fileEndpoint(id string) (string, error) {
	if strings.TrimSpace(id) == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\?#\x00") {
		return "", errors.New("file ID must be a nonempty path segment")
	}
	return TenantStoreV2URI + "/files/" + id, nil
}
