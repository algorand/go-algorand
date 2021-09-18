package logic

// AssemblyDetails contains details from the source to assembly process
// Right now it is just the map of line number to program counter or byte position in
// the assembled program but may contain other details like ABI spec or Template Variable
// relative positions in the future
type AssemblyMap struct {
	TemplateLabels map[string]TemplateVariable `json:"template_labels"`
	LineMap        []int                       `json:"line_map"`
}

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
