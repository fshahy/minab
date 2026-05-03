NIM      := nim
NIMFLAGS := -d:release

.PHONY: all clean

all: blocker.bin

blocker.bin: blocker.nim
	$(NIM) c $(NIMFLAGS) -o:blocker.bin $<

clean:
	rm -f blocker.bin
	rm -rf nimcache
