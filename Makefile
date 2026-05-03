NIM      := nim
MINGW    := x86_64-w64-mingw32-gcc
NIMFLAGS := -d:release

.PHONY: all linux windows clean

all: linux windows

linux: blocker bypass

windows: winbypass.exe

blocker: blocker.nim
	$(NIM) c $(NIMFLAGS) $<

bypass: bypass.nim
	$(NIM) c $(NIMFLAGS) $<

winbypass.exe: winbypass.nim windivert.h
	$(NIM) c $(NIMFLAGS) -d:windows --os:windows --cpu:amd64 \
		--cc:gcc --gcc.exe:$(MINGW) --gcc.linkerexe:$(MINGW) $<

clean:
	rm -f blocker bypass winbypass.exe
	rm -rf nimcache
