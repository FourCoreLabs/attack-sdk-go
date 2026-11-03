// Package query encodes the bracketed filters shared by v2 listing APIs.
package query

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
)

func Pagination(params url.Values, opts models.PaginationOpts) error {
	if opts.Size < 0 || opts.Offset < 0 {
		return errors.New("size and offset must not be negative")
	}
	if opts.Size > 0 {
		params.Set("size", strconv.Itoa(opts.Size))
	}
	if opts.Offset > 0 {
		params.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.Order != "" {
		for field := range strings.SplitSeq(opts.Order, ",") {
			if strings.Trim(strings.TrimSpace(field), "+-") == "" {
				return errors.New("order must contain sort field names")
			}
		}
		params.Set("order", opts.Order)
	}
	return nil
}

func Strings(params url.Values, key string, values []string) {
	if len(values) > 0 {
		params.Set("filter["+key+"]", strings.Join(values, ","))
	}
}

func Bool(params url.Values, key string, value *bool) {
	if value != nil {
		params.Set("filter["+key+"]", strconv.FormatBool(*value))
	}
}

func Time(params url.Values, key string, value time.Time) {
	if !value.IsZero() {
		params.Set("filter["+key+"]", value.Format(time.RFC3339))
	}
}

func Percentages(params url.Values, filter models.PercentageFilter) error {
	for key, value := range map[string]*uint{
		"start_blocked_percent": filter.StartBlockedPercent, "end_blocked_percent": filter.EndBlockedPercent,
		"start_success_percent": filter.StartSuccessPercent, "end_success_percent": filter.EndSuccessPercent,
		"start_detected_percent": filter.StartDetectedPercent, "end_detected_percent": filter.EndDetectedPercent,
	} {
		if value != nil {
			if *value > 100 {
				return fmt.Errorf("%s must be between 0 and 100", key)
			}
			params.Set("filter["+key+"]", strconv.FormatUint(uint64(*value), 10))
		}
	}
	return nil
}

func Outcomes(params url.Values, filter models.OutcomeFilter) error {
	if err := Percentages(params, filter.PercentageFilter); err != nil {
		return err
	}
	if filter.StartTotal != nil {
		params.Set("filter[start_total]", strconv.FormatUint(*filter.StartTotal, 10))
	}
	if filter.EndTotal != nil {
		params.Set("filter[end_total]", strconv.FormatUint(*filter.EndTotal, 10))
	}
	return nil
}
