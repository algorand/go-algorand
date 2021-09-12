package logic

// TmplPrefix is the special prefix for placeholder values to
// be tracked for template contracts
const TmplPrefix = "TMPL_"

// TemplateVariable holds the details for a special placeholder variable
// in a template contract
type TemplateVariable struct {
	SourceLine uint64 `json:"source_line"`
	Position   uint64 `json:"position"`
	IsBytes    bool   `json:"bytes"`
}
