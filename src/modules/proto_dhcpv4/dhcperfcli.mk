TARGET		:= dhcperfcli
SOURCES		:= dhcperfcli.c dpc_packet_list.c dpc_util.c

# Using FreeRADIUS libraries:
# - libfreeradius-util
# - libfreeradius-dhcpv4 (fr_dhcpv4_*)
# - libfreeradius-server (radius_pair_create)

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv4.a libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS)
