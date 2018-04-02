
# Introduction

*dhcperfcli* is a flexible DHCP test client program (built upon [FreeRADIUS](https://github.com/FreeRADIUS/freeradius-server) libraries) with which you can create arbitrary DHCP requests, send them to a DHCP server and view the replies. It can also be used for performance testing. It allows to observe how a DHCP server behaves, and measure what kind of packet rate it can handle.

Thereafter it shall also be refered to as *the program*.

*dhcperfcli* is built upon [FreeRADIUS](https://github.com/FreeRADIUS/freeradius-server) libraries. It requires FreeRADIUS sources (version 4.0) to build, and FreeRADIUS libraries and dictionaries to run.

This program is largely inspired by *dhcpclient* (the DHCP test client provided by FreeRADIUS), but goes beyond what *dhcpclient* can do.

Its core function is to send a DHCP request and receive the reply. Beyond that, *dhcperfcli* can:
- Send multiple packets, in sequence or concurrently, to one or multiple DHCP servers, from a client, a gateway, or multiple gateways.
- Build packets with input read from a file or stdin, or generate them dynamically from a template.
- Create malformed packets, to observe how the DHCP server behaves when handling them.
- Show statistics such as packets sent / received and response time, as a whole or broken down by message type.

And more!


# Installation

To install _dhcperfcli_, refer to [INSTALL.md](https://github.com/nchaigne/dhcperfcli/blob/master/INSTALL.md).


# Usage

```text
dhcperfcli [options] [<server>[:<port>] [<command>]]
```

Arguments|Description
-|-
`<server>:[<port>]` &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; | The DHCP server. If omitted, if must be specified through input items.<br>Default port is 67.
`<command>` | One of (message type): `discover`, `request`, `decline`, `release`, `inform`, `lease_query`.<br> Or (workflow): `dora`.<br>This can be omitted, in which case the message type must be provided through input items (`DHCP-Message-Type`).
`-D <dir>` | Read dictionaries from `<dir>`.<br>Default: directory `share/freeradius` of FreeRADIUS installation.
`-f <file>` | Read input items from `<file>`, in addition to stdin.<br>An input item is a list of *attribute/value pairs*. At least one such item is required, so one packet can be built.
`-g <gw>[:<port>]` | Handle packets sent as if relayed through giaddr `<gw>` (`hops`: 1, source: `<giaddr>:<port>`).<br>A comma-separated list may be specified, in which case packets will be sent using all of those gateways in a round-robin fashion.<br>Alternatively, option `-g` can be provided multiple times.
`-i <interface>` | Use this interface for unconfigured clients to broadcast through a raw socket. (This requires libpcap.)
`-I <num>` | Start generating `xid` values with `<num>`.<br>Default: 0.
`-L <seconds>` | Limit duration (beyond which no new session will be started).
`-N <num>` | Start at most `<num>` sessions (in template mode: generate `<num>` sessions).
`-p <num>` | Send up to `<num>` session packets in parallel.<br>Default: 1 (packets are sent sequentially).
`-P <num>` | Packet trace level (0: none, 1: header, 2: and attributes, 3: and encoded hex data).<br>A default is figured out according to number of packets and parallelism.
`-r <num>` | Rate limit (maximum packet replies /s).
`-R` | Randomize template variable values (default is to increment).<br>Refer to *template* section for details.
`-s <seconds>` | Periodically report progress statistics information.
`-t <timeout>` | Wait at most `<timeout>` seconds for a reply (may be a floating point number).<br>Default: 3.
`-T` | Template mode. Sessions input is generated from invariant and variable input items.<br>Refer to *template* section for details.
`-v` | Print program version information.
`-x` | Turn on additional debugging. (`-xx` gives more debugging, up to `-xxxx`).
`-X` | Turn on FreeRADIUS libraries debugging (use this in conjunction with `-x`).


# Examples

Refer to [usage-examples.md.md](https://github.com/nchaigne/dhcperfcli/blob/master/doc/usage-examples.md).


# Guide

## Input items

The program uses *input items* to build the DHCP packets.
An input item is a list of *attribute/value pairs* (or just *value pairs*) that are provided through standard input and/or a file. An attribute corresponds to an element of the DHCP packet (field or option).

An *value pair* is specified as follows:

`<attribute name> = <value>`

The name of DHCP attributes (along with their type, and enumerated values if applicable) are defined in [FreeRADIUS DHCP dictionary](https://github.com/FreeRADIUS/freeradius-server/blob/v4.0.x/share/dictionary.dhcp).


For example:

```text
DHCP-Transaction-Id = 42
DHCP-Client-Hardware-Address = 50:41:4e:44:41:00
DHCP-Message-Type = DHCP-Discover
```

In this example, DHCP fields `xid` and `chaddr` are provided, as well as DHCP option 53 (DHCP Message Type).

You do not need to provide attributes for DHCP fields `op`, `htype`, `hlen`. These are set automatically.<br>
Field `xid` can be omitted, in which case the program will provide a value.<br>
The message type can also be provided through command line argument `<command>`. As a rule, values obtained from input items always take precedence over arguments.

Two input items are separated by an empty line.<br>
If the input is provided through stdin, this can be achieved with __`echo -e "\n\n"`__.

In addition to DHCP attributes, the program accepts a few control attributes (whose purpose is self-explanatory) in input items:
- Packet-Src-IP-Address
- Packet-Dst-IP-Address
- Packet-Src-Port
- Packet-Dst-Port

Finally, a specific control attribute, through which you can provided DHCP pre-encoded data (not necessarily well formed, this is entirely up to you):
- DHCP-Encoded-Data

## DHCP pre-encoded data

Instead of letting the program encode your DHCP packet, you can do it yourself. This is achieved through a special control attribute: `DHCP-Encoded-Data`.<br>
If provided, all DHCP value pairs are ignored. The command `argument` should be omitted (it is ignored). Other control attributes (such as `Packet-Src-IP-Address`) can be provided.

This has several purposes:
- You can extract the content of a real DHCP packet from a network capture, for example using Wireshark (select a packet, right click on "Bootstrap Protocol" / "Copy" / "... as a Hex Stream"), then feed it (altered or not) to *dhcperfcli*.

- You can create purposely malformed data. This allows to see how the DHCP server behaves when handling such a packet.

For example:

>__`
echo "DCP-Encoded-Data=0x0101060100000001000000000000000000000000000000000000000050414e444100"  |  dhcperfcli  -i eth0 -P 3  255.255.255.255
`__

This is obviously malformed data: it ends right after the first 6 octets of field `chaddr` (the client MAC address).
You can send it, but you won't get a reply from any sane DHCP server (for that you need to provide at least option 53 *Message Type*). Actually, the program won't even wait for a reply (because it doesn't think one is expected).

Another example:
>__`
echo "DCP-Encoded-Data=0x0101060100000001000000000000000000000000000000000000000050414e4441000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101ff"  |  dhcperfcli  -i eth0 -P 3  255.255.255.255
`__

This one is a well-formed (if a bit hard to read, but option `-P 3` will display something more accessible) DHCP Discover packet, to which you can get a DHCP Offer reply.
