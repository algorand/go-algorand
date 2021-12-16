package logic

// SourceMapper provides an interface for mapping between a TEAL source file and
// an assembled program.
type SourceMapper interface {
	Name() string
	Version() int
	NumLines() int
	LineToPc(line int) (pc int, ok bool)
	PcToLine(pc int) (line int, ok bool)
}

// AssemblyMap contains details from the source to assembly process
// currently contains map of TEAL source line number to assembled bytecode position
// and details about the template varirables contained in the source file
type AssemblyMap struct {
	SourceName     string                      `json:"name"`
	SourceVersion  int                         `json:"version"`
	TemplateLabels map[string]TemplateVariable `json:"template_labels"`
	LineMap        []int                       `json:"line_map"`
}

var _ SourceMapper = &AssemblyMap{}

func (am *AssemblyMap) Name() string {
	return am.SourceName
}

func (am *AssemblyMap) Version() int {
	return am.SourceVersion
}

func (am *AssemblyMap) NumLines() int {
	return len(am.LineMap)
}

func (am *AssemblyMap) LineToPc(line int) (int, bool) {
	if line >= len(am.LineMap) {
		return 0, false
	}

	var pc int
	// If its an empty line, we need to go back to the first non-empty line
	for idx := line; idx > 0; idx-- {
		pc = am.LineMap[line]
		if pc != 0 {
			return pc, true
		}
	}

	return 0, false
}

func (am *AssemblyMap) PcToLine(pc int) (int, bool) {
	for idx, p := range am.LineMap {
		if p == pc {
			return idx, true
		}
	}

	return 0, false
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
