NIM      := nim
NIMFLAGS := -d:release

.PHONY: all clean

all: blocker

blocker: blocker.nim
	$(NIM) c $(NIMFLAGS) $<

clean:
	rm -f blocker
	rm -rf nimcache
