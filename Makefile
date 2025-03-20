INPUT=README.md
OUTPUT=README.pdf

PANDOC=pandoc
PANDOC_OPTS=--pdf-engine=xelatex \
	--toc \
	--toc-depth=3 \
	--wrap=auto \
	-V geometry:margin=1in \
	-V fontsize=11pt

all: $(OUTPUT)

$(OUTPUT): $(INPUT)
	$(PANDOC) $(PANDOC_OPTS) -o $(OUTPUT) $(INPUT)

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
