package json

import (
	"encoding/json"
	"io"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
)

type jsonRenderer struct{}

func (r *jsonRenderer) Render(w io.Writer, items []any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}

func NewJsonRender() renderers.Renderer {
	return &jsonRenderer{}
}
