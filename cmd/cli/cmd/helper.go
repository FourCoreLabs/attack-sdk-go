package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/fourcorelabs/attack-sdk-go/pkg/models"
	"github.com/fourcorelabs/attack-sdk-go/pkg/view"
	"github.com/spf13/cobra"
)

func resolveOutputOptions(format, mode string, modeChanged bool) (view.Format, view.Mode, error) {
	resolvedFormat, err := view.NormalizeFormat(format)
	if err != nil {
		return "", "", err
	}

	if modeChanged {
		resolvedMode, err := view.NormalizeMode(mode)
		if err != nil {
			return "", "", err
		}

		return resolvedFormat, resolvedMode, nil
	}

	if resolvedFormat == view.FormatJSON {
		return resolvedFormat, view.ModeExpanded, nil
	}

	return resolvedFormat, view.ModeSummary, nil
}

type renderOutputOpt struct {
	composeFirstDataElem bool

	isEmpty      bool
	emptyMessage string

	totalLabel string
	totalValue int
	showTotal  bool
}

func renderOutput(writer io.Writer, format, mode string, data []any, opt renderOutputOpt) error {
	if opt.isEmpty {
		if opt.emptyMessage == "" {
			return nil
		}
		_, err := fmt.Fprintln(writer, opt.emptyMessage)
		return err
	}

	if opt.showTotal && opt.totalLabel != "" {
		if _, err := fmt.Fprintf(writer, "%s: %d\n\n", opt.totalLabel, opt.totalValue); err != nil {
			return err
		}
	}

	v, err := view.New(format, mode, data)
	if err != nil {
		return err
	}

	return v.Render(writer)
}

func outputItems[T, W any](cmd *cobra.Command, format, mode string, modeChanged bool, src []T, wrap func(T) W, emptyMessage string) error {
	resolvedFormat, resolvedMode, err := resolveOutputOptions(format, mode, modeChanged)
	if err != nil {
		return err
	}

	items := make([]W, 0, len(src))
	for _, item := range src {
		items = append(items, wrap(item))
	}

	data, err := view.Materialize(items, resolvedMode)
	if err != nil {
		return err
	}

	return renderOutput(
		cmd.OutOrStdout(),
		string(resolvedFormat),
		string(resolvedMode),
		data,
		renderOutputOpt{
			isEmpty:      len(items) == 0,
			emptyMessage: emptyMessage,
		},
	)
}

func outputPaginatedItems[T, W any](cmd *cobra.Command, format, mode string, modeChanged bool, src models.PaginationResponse[T], wrap func(T) W, emptyMessage, totalLabel string) error {
	resolvedFormat, resolvedMode, err := resolveOutputOptions(format, mode, modeChanged)
	if err != nil {
		return err
	}

	items := make([]W, 0, len(src.Data))
	for _, item := range src.Data {
		items = append(items, wrap(item))
	}

	var data []any
	opt := renderOutputOpt{
		isEmpty:      len(src.Data) == 0,
		emptyMessage: emptyMessage,
		totalLabel:   totalLabel,
		totalValue:   src.TotalRows,
		showTotal:    true,
	}

	if resolvedMode == view.ModeExpanded {
		data = append(data, src)
		opt.composeFirstDataElem = true
	} else if data, err = view.Materialize(items, resolvedMode); err != nil {
		return err
	}

	return renderOutput(
		cmd.OutOrStdout(),
		string(resolvedFormat),
		string(resolvedMode),
		data,
		opt,
	)
}

func outputListWithCountItems[T, W any](cmd *cobra.Command, format, mode string, modeChanged bool, src models.ListWithCount[T], wrap func(T) W, emptyMessage, totalLabel string) error {
	resolvedFormat, resolvedMode, err := resolveOutputOptions(format, mode, modeChanged)
	if err != nil {
		return err
	}

	items := make([]W, 0, len(src.Data))
	for _, item := range src.Data {
		items = append(items, wrap(item))
	}

	var data []any
	opt := renderOutputOpt{
		isEmpty:      src.Count == 0 || len(src.Data) == 0,
		emptyMessage: emptyMessage,
		totalLabel:   totalLabel,
		totalValue:   src.Count,
		showTotal:    true,
	}

	if resolvedMode == view.ModeExpanded {
		data = append(data, src)
		opt.composeFirstDataElem = true
	} else if data, err = view.Materialize(items, resolvedMode); err != nil {
		return err
	}

	return renderOutput(
		cmd.OutOrStdout(),
		string(resolvedFormat),
		string(resolvedMode),
		data,
		opt,
	)
}

func printJSON(w io.Writer, payload any) error {
	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON output: %w", err)
	}

	_, err = fmt.Fprintln(w, string(jsonData))
	return err
}
