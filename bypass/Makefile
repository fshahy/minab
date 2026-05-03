NIM      := nim
NIMFLAGS := -d:release

.PHONY: all clean

all: bypass

bypass: bypass.nim
	$(NIM) c $(NIMFLAGS) $<

clean:
	rm -f bypass
	rm -rf nimcache
