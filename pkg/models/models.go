package models

type OrderBy struct {
	Name string
	Asc  bool // default to desc (asc false)
}

type FilterBy struct {
	Name  string
	Value []string
}

type Pagination struct {
	Offset      uint64     `json:"offset" example:"1" description:"set offset"`
	Size        uint64     `json:"size"`
	OrderQuery  []OrderBy  `json:"order"`
	FilterQuery []FilterBy `json:"-"`
}

type PaginationResponse[Data any] struct {
	Pagination
	TotalRows int    `json:"total_rows" example:"50"`
	Data      []Data `json:"data"`
}
