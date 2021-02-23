all:	TEAL_opcodes.md README.md fields_string.go

# Location of algorandfoundation/specs repo. (Optional)
SPECS := ../../../../specs

TEAL_opcodes.md:	fields_string.go ../../../cmd/opdoc/opdoc.go eval.go assembler.go doc.go opcodes.go
	go run ../../../cmd/opdoc/opdoc.go ../../../cmd/opdoc/tmLanguage.go
	if [ -e $(SPECS)/dev/TEAL_opcodes.md ]; then \
		sed '/^$$/q' $(SPECS)/dev/TEAL_opcodes.md | cat - TEAL_opcodes.md > opcodes.spec; \
		mv opcodes.spec $(SPECS)/dev/TEAL_opcodes.md; \
	fi

fields_string.go:	fields.go
	go generate

README.md:	TEAL_opcodes.md README_in.md
	python merge.py > README.md
	if [ -e $(SPECS)/dev/TEAL.md ]; then \
		sed '/^$$/q' $(SPECS)/dev/TEAL.md | cat - README.md > teal.spec; \
                mv teal.spec $(SPECS)/dev/TEAL.md; \
	fi
