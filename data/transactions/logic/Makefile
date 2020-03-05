all:	TEAL_opcodes.md wat.md

TEAL_opcodes.md:	../../../cmd/opdoc/opdoc.go eval.go assembler.go doc.go opcodes.go
	go run ../../../cmd/opdoc/opdoc.go

wat.md:	TEAL_opcodes.md README_in.md
	python merge.py > README.md
