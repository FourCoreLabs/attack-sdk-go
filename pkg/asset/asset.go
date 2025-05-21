package asset

import (
	"fmt"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/models/asset"
)

// AssetsV2URI is the base endpoint for the assets API
const AssetsV2URI = "/api/v2/assets"

// EmailAssetsV2URI is the base endpoint for the email assets API
const EmailAssetsV2URI = "/api/v2/assets/email"

// GetAssets retrieves all assets from the API
func GetAssets(h *api.HTTPAPI) ([]asset.Asset, error) {
	var assets []asset.Asset

	_, err := h.GetJSON(AssetsV2URI, &assets)
	return assets, err
}

// GetAsset retrieves a specific asset by ID
func GetAsset(h *api.HTTPAPI, assetID string) (asset.Asset, error) {
	var assetData asset.Asset

	_, err := h.GetJSON(fmt.Sprintf("%s/%s", AssetsV2URI, assetID), &assetData)
	return assetData, err
}

// DisableAsset disables an asset by ID
func DisableAsset(h *api.HTTPAPI, assetID string) (models.SuccessIDResponse, error) {
	var response models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s/disable", AssetsV2URI, assetID)
	_, err := h.PostJSON(endpoint, nil, &response)
	return response, err
}

// EnableAsset enables an asset by ID
func EnableAsset(h *api.HTTPAPI, assetID string) (models.SuccessIDResponse, error) {
	var response models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s/enable", AssetsV2URI, assetID)
	_, err := h.PostJSON(endpoint, nil, &response)
	return response, err
}

// DeleteAsset deletes an asset by ID
func DeleteAsset(h *api.HTTPAPI, assetID string) (models.SuccessIDResponse, error) {
	var response models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s", AssetsV2URI, assetID)
	_, err := h.DeleteJSON(endpoint, nil, &response)
	return response, err
}

// GetAssetAnalytics retrieves analytics data for an asset
func GetAssetAnalytics(h *api.HTTPAPI, assetID string, days int) (asset.AssetAnalytics, error) {
	var analytics asset.AssetAnalytics

	endpoint := fmt.Sprintf("%s/%s/analytics", AssetsV2URI, assetID)
	_, err := h.GetJSON(endpoint, &analytics, api.ReqOptions{
		Params: map[string]string{
			"d": fmt.Sprintf("%d", days),
		},
	})
	return analytics, err
}

// SetAssetTags updates the tags for an asset
func SetAssetTags(h *api.HTTPAPI, assetID string, tags map[string]string) (asset.AssetSetTagsResponse, error) {
	var response asset.AssetSetTagsResponse

	endpoint := fmt.Sprintf("%s/%s/tags", AssetsV2URI, assetID)
	tagData := asset.AssetTags{Tags: tags}

	_, err := h.PostJSON(endpoint, tagData, &response)
	return response, err
}

// GetAssetAttacksOpts represents options for listing asset attacks
type GetAssetAttacksOpts struct {
	Size   int
	Offset int
	Order  string
	Name   string
}

// GetAssetExecutionsOpts represents options for listing asset executions
type GetAssetExecutionsOpts struct {
	Size   int
	Offset int
	Order  string
	Name   string
}

// GetAssetAttacks retrieves attack executions for a specific asset
func GetAssetAttacks(h *api.HTTPAPI, assetID string, opts GetAssetAttacksOpts) (models.ListWithCount, error) {
	var attacks models.ListWithCount

	endpoint := fmt.Sprintf("%s/%s/attacks", AssetsV2URI, assetID)
	params := map[string]string{
		"size":   fmt.Sprintf("%d", opts.Size),
		"offset": fmt.Sprintf("%d", opts.Offset),
		"order":  opts.Order,
	}

	if opts.Name != "" {
		params["name"] = opts.Name
	}

	_, err := h.GetJSON(endpoint, &attacks, api.ReqOptions{Params: params})
	return attacks, err
}

// GetAssetExecutions retrieves execution reports for a specific asset
func GetAssetExecutions(h *api.HTTPAPI, assetID string, opts GetAssetExecutionsOpts) (models.ListWithCount, error) {
	var executions models.ListWithCount

	endpoint := fmt.Sprintf("%s/%s/executions", AssetsV2URI, assetID)
	params := map[string]string{
		"size":   fmt.Sprintf("%d", opts.Size),
		"offset": fmt.Sprintf("%d", opts.Offset),
		"order":  opts.Order,
	}

	if opts.Name != "" {
		params["name"] = opts.Name
	}

	_, err := h.GetJSON(endpoint, &executions, api.ReqOptions{Params: params})
	return executions, err
}

// GetAssetPacks retrieves assessment reports for a specific asset
func GetAssetPacks(h *api.HTTPAPI, assetID string, opts GetAssetExecutionsOpts) ([]models.PackRun, error) {
	var packs []models.PackRun

	endpoint := fmt.Sprintf("%s/%s/packs", AssetsV2URI, assetID)
	params := map[string]string{
		"size":   fmt.Sprintf("%d", opts.Size),
		"offset": fmt.Sprintf("%d", opts.Offset),
		"order":  opts.Order,
	}

	if opts.Name != "" {
		params["name"] = opts.Name
	}

	_, err := h.GetJSON(endpoint, &packs, api.ReqOptions{Params: params})
	return packs, err
}

// GetEmailAssets retrieves all email assets from the API
func GetEmailAssets(h *api.HTTPAPI) ([]asset.EmailAsset, error) {
	var assets []asset.EmailAsset

	_, err := h.GetJSON(EmailAssetsV2URI, &assets)
	return assets, err
}

// GetEmailAsset retrieves a specific email asset by ID
func GetEmailAsset(h *api.HTTPAPI, assetID string) (asset.EmailAsset, error) {
	var assetData asset.EmailAsset

	_, err := h.GetJSON(fmt.Sprintf("%s/%s", EmailAssetsV2URI, assetID), &assetData)
	return assetData, err
}

// CreateEmailAsset creates a new email asset
func CreateEmailAsset(h *api.HTTPAPI, email string, tags map[string]string) (asset.EmailAsset, error) {
	var assetData asset.EmailAsset

	reqBody := asset.CreateEmailAssetRequest{
		Email: email,
		Tags:  tags,
	}

	_, err := h.PostJSON(EmailAssetsV2URI, reqBody, &assetData)
	return assetData, err
}

// UpdateEmailAsset updates an existing email asset
func UpdateEmailAsset(h *api.HTTPAPI, assetID string, email string, tags map[string]string) (models.SuccessIDResponse, error) {
	var response models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s", EmailAssetsV2URI, assetID)
	reqBody := asset.CreateEmailAssetRequest{
		Email: email,
		Tags:  tags,
	}

	_, err := h.PutJSON(endpoint, reqBody, &response)
	return response, err
}

// DeleteEmailAsset deletes an email asset by ID
func DeleteEmailAsset(h *api.HTTPAPI, assetID string) (models.SuccessIDResponse, error) {
	var response models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s", EmailAssetsV2URI, assetID)
	_, err := h.DeleteJSON(endpoint, nil, &response)
	return response, err
}

// VerifyEmailAsset sends a verification email for an email asset
func VerifyEmailAsset(h *api.HTTPAPI, assetID string) (models.SuccessIDResponse, error) {
	var response models.SuccessIDResponse

	endpoint := fmt.Sprintf("%s/%s/verify", EmailAssetsV2URI, assetID)
	_, err := h.PostJSON(endpoint, nil, &response)
	return response, err
}

// GetEmailAssetAnalytics retrieves analytics data for an email asset
func GetEmailAssetAnalytics(h *api.HTTPAPI, assetID string, days int) (asset.EmailAssetAnalytics, error) {
	var analytics asset.EmailAssetAnalytics

	endpoint := fmt.Sprintf("%s/%s/analytics", EmailAssetsV2URI, assetID)
	_, err := h.GetJSON(endpoint, &analytics, api.ReqOptions{
		Params: map[string]string{
			"d": fmt.Sprintf("%d", days),
		},
	})
	return analytics, err
}

// GetGmailConfirmationCode retrieves the Gmail confirmation code for an email asset
func GetGmailConfirmationCode(h *api.HTTPAPI, assetID string) (asset.GmailConfCode, error) {
	var confCode asset.GmailConfCode

	endpoint := fmt.Sprintf("%s/%s/gmail/confirmation", EmailAssetsV2URI, assetID)
	_, err := h.GetJSON(endpoint, &confCode)
	return confCode, err
}
