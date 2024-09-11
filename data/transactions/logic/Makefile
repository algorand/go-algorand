all:	TEAL_opcodes.md teal.tmLanguage.json README.md fields_string.go

# Location of algorandfoundation/specs repo. (Optional)
SPECS := ../../../../specs
# Location of algorand/docs repo. (Optional)
DOCS :=  ../../../../docs

TEAL_opcodes.md teal.tmLanguage.json:	fields_string.go ../../../cmd/opdoc/opdoc.go ../../../cmd/opdoc/tmLanguage.go eval.go assembler.go doc.go opcodes.go
	go run ../../../cmd/opdoc/opdoc.go ../../../cmd/opdoc/tmLanguage.go
	@cp `ls TEAL_opcodes_v??.md | tail -1` TEAL_opcodes.md
	@if [ -e $(SPECS)/dev/TEAL_opcodes.md ]; then \
		sed '/^$$/q' $(SPECS)/dev/TEAL_opcodes.md | cat - TEAL_opcodes.md > opcodes.spec; \
		mv opcodes.spec $(SPECS)/dev/TEAL_opcodes.md; \
		echo "TEAL_opcodes.md updated in specs repo"; \
	fi
	@rm TEAL_opcodes.md

fields_string.go:	fields.go
	go generate

README.md:	TEAL_opcodes.md README_in.md
	python3 merge.py > README.md
	@if [ -e $(SPECS)/dev/TEAL.md ]; then \
		sed '/^$$/q' $(SPECS)/dev/TEAL.md | cat - README.md > teal.spec; \
		mv teal.spec $(SPECS)/dev/TEAL.md; \
		echo "TEAL.md updated in specs repo"; \
	fi

clean:
	rm -f TEAL_opcodes*.md langspec_v*.json README.md fields_string.go
