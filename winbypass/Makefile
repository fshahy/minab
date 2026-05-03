NIM      := nim
MINGW    := x86_64-w64-mingw32-gcc
NIMFLAGS := -d:release

.PHONY: all clean

all: winbypass.exe

winbypass.exe: winbypass.nim windivert.h
	$(NIM) c $(NIMFLAGS) -d:windows --os:windows --cpu:amd64 \
		--cc:gcc --gcc.exe:$(MINGW) --gcc.linkerexe:$(MINGW) $<

clean:
	rm -f winbypass.exe
	rm -rf nimcache
