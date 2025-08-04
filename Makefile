# tools (override on the CLI if you need clang or mingw-w64)
CC          ?= gcc
AR          ?= ar
GO          ?= go

# directories / files
C_SRC       := $(wildcard C/*.c)
C_OBJ       := $(patsubst %.c,%.o,$(C_SRC))
C_LIB       := C/libsniffer.a

# tell CGO where headers and our static lib live
export CGO_CFLAGS  := -I$(CURDIR)/C
export CGO_LDFLAGS := -L$(CURDIR)/C -lsniffer -lpcap   # -lpcap brings in the system pcap library :contentReference[oaicite:2]{index=2}

.PHONY: all lib go vet run clean

# ----- default: build C then Go -----------------------------------
all: lib
	$(GO) build ./cmd/fynewire

# ----- build the static C library ---------------------------------
lib: $(C_LIB)

$(C_LIB): $(C_OBJ)
	$(AR) rcs $@ $^

# compile .c → .o  (-fPIC allows CGO to link it on all platforms) :contentReference[oaicite:3]{index=3}
C/%.o: C/%.c C/sniffer.h
	$(CC) -Wall -O2 -fPIC -c $< -o $@

# ----- secondary helpers ------------------------------------------
vet:
	$(GO) vet ./...

run: all
	$(GO) run ./cmd/fynewire

clean:
	rm -f $(C_OBJ) $(C_LIB)
	$(GO) clean -cache -testcache
# ------------------------------------------------------------------
