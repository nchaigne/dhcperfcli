TARGET		:= dhcperfcli
SOURCES		:= dhcperfcli.c
SOURCES		+= ncc_util.c ncc_xlat_core.c ncc_xlat_func.c
SOURCES		+= dpc_config.c dpc_packet_list.c dpc_util.c dpc_xlat.c

# Using FreeRADIUS libraries:
# - libfreeradius-util
# - libfreeradius-dhcpv4 (fr_dhcpv4_*)
# - libfreeradius-server, libfreeradius-unlang (for xlat engine)

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-dhcpv4.a
TGT_PREREQS	+= libfreeradius-unlang.a libfreeradius-server.a

TGT_LDLIBS	:= $(LIBS)
