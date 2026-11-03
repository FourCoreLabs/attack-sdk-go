package json

import (
	"encoding/json"
	"io"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
)

type jsonRenderer struct{}

var _ renderers.Renderer = (*jsonRenderer)(nil)

// NewJsonRender creates a JSON renderer.
//
// Required permission: none (local operation).
func NewJsonRender() renderers.Renderer {
	return &jsonRenderer{}
}

// Render writes items as indented JSON to w.
//
// Required permission: none (local rendering).
func (r *jsonRenderer) Render(w io.Writer, items []any, opts ...renderers.RendererOptFunc) error {
	opt := renderers.RendererOption{}
	for _, fn := range opts {
		fn(&opt)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if opt.SingleElemAndCompose {
		if len(items) == 0 {
			return nil
		}
		return enc.Encode(items[0])
	}

	return enc.Encode(items)
}
