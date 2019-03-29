TARGET		:= dhcperfcli
SOURCES		:= dhcperfcli.c ncc_util.c dpc_packet_list.c dpc_util.c ncc_xlat_core.c

# Using FreeRADIUS libraries:
# - libfreeradius-util
# - libfreeradius-dhcpv4 (fr_dhcpv4_*)
# - libfreeradius-unlang (for xlat engine)

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv4.a
TGT_PREREQS	+= libfreeradius-unlang.a libfreeradius-server.a

TGT_LDLIBS	:= $(LIBS)
