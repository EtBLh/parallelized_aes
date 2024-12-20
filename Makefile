CC = gcc
OBJS = aes.o
OUTDIR = out
SRCDIR = src

.PHONY: clean all

tester:
	$(CC) -O2 $@.c -o $(OUTDIR)/$@.o

%:
	$(CC) -O2 -I$(SRCDIR) $@.c -o $(OUTDIR)/$@.o

clean:
	@echo "cleaning outdir"
	-rm ./out/*

all:
	@echo all