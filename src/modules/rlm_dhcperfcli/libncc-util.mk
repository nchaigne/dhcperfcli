TARGET := libncc-util.a

SOURCES := \
	ncc_log.c \
	ncc_parse.c \
	ncc_segment.c \
	ncc_util.c

# System libraries discovered by top level configure script
TGT_LDLIBS  := $(LIBS)
TGT_LDFLAGS := $(LDFLAGS)

TGT_PREREQS += libfreeradius-util.a

$(info libncc-util: TGT_LDLIBS  = $(TGT_LDLIBS))
$(info libncc-util: TGT_LDFLAGS = $(TGT_LDFLAGS))
$(info libncc-util: TGT_PREREQS = $(TGT_PREREQS))
