CC = gcc
OUTDIR = out
SRCDIR = src
CFLAGS = -O2
DEP = $(SRCDIR)/serial.c $(SRCDIR)/common.c

.PHONY: clean all

tester_openmp: CFLAGS += -fopenmp
tester_openmp: DEP += $(SRCDIR)/openmp.c

tester_pthread: CFLAGS += -lopenmp
tester_pthread: DEP += $(SRCDIR)/pthread.c

tester_aesni: CFLAGS += -maes
tester_aesni: DEP += $(SRCDIR)/aesni.c

tester_%:
	$(CC) $(CFLAGS) -I$(SRCDIR) $@.c $(DEP) -o $(OUTDIR)/$@.o 

clean:
	@echo "cleaning outdir"
	-rm ./out/*

all: tester_serial tester_aesni