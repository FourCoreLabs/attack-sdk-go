package view

import (
	"fmt"
	"io"
	"iter"
	"strings"
)

type Format string

const (
	FormatJSON  Format = "json"
	FormatTable Format = "table"
	FormatCSV   Format = "csv"
)

type Mode string

const (
	ModeSummary  Mode = "summary"
	ModeExpanded Mode = "expanded"
)

type Transformable interface {
	Transform() (any, error)
}

type Summarizable interface {
	Summary() (any, error)
}

type View[T any] struct {
	Format Format
	Mode   Mode
	Data   iter.Seq2[T, error]
	vr     *ViewRender
}

type ViewOpts[T any] func(*View[T]) error

func New[T any](format, mode string, data iter.Seq2[T, error], opts ...ViewOpts[T]) (*View[T], error) {
	f, err := normalizeFormat(format)
	if err != nil {
		return nil, err
	}

	m, err := normalizeMode(mode)
	if err != nil {
		return nil, err
	}

	v := &View[T]{
		Format: f,
		Mode:   m,
		Data:   data,
	}

	for _, fn := range opts {
		if err := fn(v); err != nil {
			return v, err
		}
	}

	if v.vr == nil {
		rf, err := NewViewRender()
		if err != nil {
			return v, err
		}
		v.vr = rf
	}

	return v, nil
}

func WithViewRender[T any](vr *ViewRender) ViewOpts[T] {
	return func(v *View[T]) error {
		v.vr = vr
		return nil
	}
}

func (v *View[T]) Render(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("writer cannot be nil")
	}

	renderer, err := v.vr.GetRenderer(v.Format)
	if err != nil {
		return err
	}

	items, err := v.materialize()
	if err != nil {
		return err
	}

	return renderer.Render(w, items)
}

func (v *View[T]) materialize() ([]any, error) {
	if v == nil {
		return nil, nil
	}

	items := make([]any, 0)
	for item, err := range v.Data {
		if err != nil {
			return nil, err
		}

		processed, err := processItem(any(item), v.Mode)
		if err != nil {
			return nil, err
		}

		items = append(items, processed)
	}

	return items, nil
}

func processItem(item any, mode Mode) (d any, err error) {
	expanded := item
	if transformer, ok := item.(Transformable); ok {
		transformed, err := transformer.Transform()
		if err != nil {
			return nil, err
		}
		expanded = transformed
	}

	if mode != ModeSummary {
		return expanded, nil
	}

	if summarizer, ok := expanded.(Summarizable); ok {
		return summarizer.Summary()
	}

	return expanded, nil
}

func normalizeFormat(format string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(format)))
	switch f {
	case FormatJSON, FormatTable, FormatCSV:
		return f, nil
	default:
		return "", fmt.Errorf("invalid format %q", format)
	}
}

func normalizeMode(mode string) (Mode, error) {
	m := Mode(strings.ToLower(strings.TrimSpace(mode)))
	switch m {
	case ModeSummary, ModeExpanded:
		return m, nil
	default:
		return "", fmt.Errorf("invalid mode %q", mode)
	}
}
