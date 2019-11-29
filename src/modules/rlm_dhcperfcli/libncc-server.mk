TARGET := libncc-server.a

SOURCES := \
	ncc_util_server.c

# System libraries discovered by top level configure script
TGT_LDLIBS  := $(LIBS)
TGT_LDFLAGS := $(LDFLAGS)

TGT_PREREQS += libfreeradius-util.a
TGT_PREREQS += libfreeradius-unlang.a libfreeradius-server.a

$(info libncc-server: TGT_LDLIBS  = $(TGT_LDLIBS))
$(info libncc-server: TGT_LDFLAGS = $(TGT_LDFLAGS))
$(info libncc-server: TGT_PREREQS = $(TGT_PREREQS))
