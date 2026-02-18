all:	teal.tmLanguage.json README.md fields_string.go

# Location of algorandfoundation/specs repo. (Optional)
SPECS := ../../../../specs

teal.tmLanguage.json:	fields_string.go ../../../cmd/opdoc/opdoc.go ../../../cmd/opdoc/tmLanguage.go eval.go assembler.go doc.go opcodes.go
	go run ../../../cmd/opdoc/opdoc.go ../../../cmd/opdoc/tmLanguage.go
	@cp `ls TEAL_opcodes_v??.md | tail -1` avm-appendix-a.md
	@if [ -e $(SPECS)/src/avm/avm-appendix-a.md ]; then \
		cp avm-appendix-a.md $(SPECS)/src/avm/avm-appendix-a.md; \
		cp avm-stack-types.md $(SPECS)/src/_include/auto/; \
		cp constants-*.md $(SPECS)/src/_include/auto/; \
		cp account-access.md $(SPECS)/src/_include/auto/opcodes/; \
		cp application-access.md $(SPECS)/src/_include/auto/opcodes/; \
		cp arithmetic.md $(SPECS)/src/_include/auto/opcodes/; \
		cp asset-access.md $(SPECS)/src/_include/auto/opcodes/; \
		cp block-access.md $(SPECS)/src/_include/auto/opcodes/; \
		cp box-access.md $(SPECS)/src/_include/auto/opcodes/; \
		cp byte-array-arithmetic.md $(SPECS)/src/_include/auto/opcodes/; \
		cp byte-array-logic.md $(SPECS)/src/_include/auto/opcodes/; \
		cp byte-array-manipulation.md $(SPECS)/src/_include/auto/opcodes/; \
		cp cryptography.md $(SPECS)/src/_include/auto/opcodes/; \
		cp flow-control.md $(SPECS)/src/_include/auto/opcodes/; \
		cp inner-transactions.md $(SPECS)/src/_include/auto/opcodes/; \
		cp loading-values.md $(SPECS)/src/_include/auto/opcodes/; \
		echo "Updates in specs repo."; \
	fi

fields_string.go:	fields.go
	go generate

clean:
	rm -f TEAL_opcodes*.md langspec_v*.json README.md fields_string.go
