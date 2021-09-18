package logic

// AssemblyMap contains details from the source to assembly process
// currently contains map of TEAL source line number to assembled bytecode position
// and details about the template varirables contained in the source file
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
