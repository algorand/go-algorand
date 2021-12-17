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
	SourceName    string `json:"name"`
	SourceVersion int    `json:"version"`
	LineMap       []int  `json:"line_map"`
}

var _ SourceMapper = &AssemblyMap{}

// Name returns the source file name
func (am *AssemblyMap) Name() string {
	return am.SourceName
}

// Version returns the teal version
func (am *AssemblyMap) Version() int {
	return am.SourceVersion
}

// NumLines returns the number of lines in the source file
func (am *AssemblyMap) NumLines() int {
	return len(am.LineMap)
}

// LineToPc maps a line number to the pc (ie program counter, the byte index in the assembled file)
func (am *AssemblyMap) LineToPc(line int) (int, bool) {
	if line >= len(am.LineMap) {
		return 0, false
	}

	// First line should always map to 0
	if line == 0 {
		return 0, true
	}

	var pc int
	// If its an empty line, we should go back to the first non-empty line
	for idx := line; idx > 0; idx-- {
		pc = am.LineMap[line]
		if pc != 0 {
			return pc, true
		}
	}

	return 0, false
}

// PcToLine maps a pc to the line number in the source file
func (am *AssemblyMap) PcToLine(pc int) (int, bool) {
	for idx, p := range am.LineMap {
		if p == pc {
			return idx, true
		}
	}

	return 0, false
}
