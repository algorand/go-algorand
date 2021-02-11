all:	TEAL_opcodes.md README.md fields_string.go

TEAL_opcodes.md:	fields_string.go ../../../cmd/opdoc/opdoc.go eval.go assembler.go doc.go opcodes.go
	go run ../../../cmd/opdoc/opdoc.go ../../../cmd/opdoc/tmLanguage.go

fields_string.go:	fields.go
	go generate

README.md:	TEAL_opcodes.md README_in.md
	python merge.py > README.md
