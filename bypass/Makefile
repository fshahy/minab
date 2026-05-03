NIM      := nim
NIMFLAGS := -d:release

.PHONY: all clean

all: bypass.bin

bypass.bin: bypass.nim
	$(NIM) c $(NIMFLAGS) -o:bypass.bin $<

clean:
	rm -f bypass.bin
	rm -rf nimcache
