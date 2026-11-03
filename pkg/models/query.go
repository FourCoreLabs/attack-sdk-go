package models

// PaginationOpts selects one page. Size zero uses the server default; negative
// sizes and offsets are invalid. Order is a comma-separated list of sort fields
// with optional +/- prefixes, for example "-release_date,name".
type PaginationOpts struct {
	Size   int
	Offset int
	Order  string
}

// PercentageFilter limits results by outcome percentages (0–100).
// Nil pointers omit a bound; a pointer to zero explicitly includes a zero bound.
type PercentageFilter struct {
	StartBlockedPercent  *uint
	EndBlockedPercent    *uint
	StartSuccessPercent  *uint
	EndSuccessPercent    *uint
	StartDetectedPercent *uint
	EndDetectedPercent   *uint
}

// OutcomeFilter adds total-count bounds to percentage filters.
type OutcomeFilter struct {
	PercentageFilter
	StartTotal *uint64
	EndTotal   *uint64
}
