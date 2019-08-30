all:	opcodes.md wat.md

opcodes.md:	../../../cmd/opdoc/opdoc.go eval.go assembler.go
	go run ../../../cmd/opdoc/opdoc.go

wat.md:	opcodes.md README_in.md
	python merge.py > README.md
