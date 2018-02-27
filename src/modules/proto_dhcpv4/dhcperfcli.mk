TARGET		:= dhcperfcli
SOURCES		:= dhcperfcli.c dpc_packet_list.c dpc_util.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv4.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
