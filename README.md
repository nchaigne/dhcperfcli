
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
- Collect time-data statistics, send them to InfluxDB, visualize the data through Grafana dashboards... all in real-time!

And more!


# Installation

To build and install *dhcperfcli*, refer to [INSTALL.md](https://github.com/nchaigne/dhcperfcli/blob/master/INSTALL.md).


# Usage

```text
dhcperfcli [options] [<server>[:<port>] [<command>]]
```

Note: some options can be provided more than once. They are identified by an asterisk (*) in the table below.

Arguments&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|Description
-|-
`<server>:[<port>]` | The DHCP server. If omitted, if must be specified through input items.<br>Default port is 67.
`<command>` | One of (message type): `discover`, `request`, `decline`, `release`, `inform`, `lease_query`.<br> Or (workflow): `dora` (Discover, Offer, Request, Ack), `doradec` (DORA followed by Decline), `dorarel` (DORA  followed by Release).<br>`<command>` can be omitted, in which case either the message type (`DHCP-Message-Type`) or workflow (`DHCP-Workflow-Type`) must be provided through input items.
`-a <ipaddr>` * | Authorized servers. Only allow replies from one of these.<br>Useful to select a DHCP server if there are several which might reply to a broadcasting client.
`-A` | Wait for multiple Offer replies to broadcast Discover (instead of only the first). This requires option `-i`.
`-c <num>` | Use each input item up to `<num>` times.<br>Default: unlimited in template mode, or 1 otherwise.
`-D <dir>` | Dictionaries main directory.<br>Default: directory `share/freeradius/dictionary` of FreeRADIUS installation.
`-f <file>` * | Read input items from `<file>`, in addition to stdin.<br>An input item is a list of *attribute/value pairs*. At least one such item is required, so one packet can be built.
`-g <gw>[:<port>]` * | Handle packets sent as if relayed through giaddr `<gw>` (`hops`: 1, source: `<giaddr>:<port>`).<br>Multiple gateways may be specified, in which case packets will be sent using all of these gateways in a round-robin fashion.
`-i <interface>` | Use this interface for unconfigured clients to broadcast through a raw socket. (This requires libpcap.)
`-I <num>` | Start generating `xid` values with `<num>`.<br>Default: random value.
`-L <seconds>` | Limit duration for starting new input sessions.
`-N <num>` | Start at most `<num>` sessions from input items.
`-p <num>` | Send up to `<num>` session initial packets in parallel.<br>Default: 1 (packets are sent sequentially).
`-P <num>` | Packet trace level (0: none, 1: header, 2: and attributes, 3: and encoded hex data).<br>A default is figured out according to number of packets and parallelism.
`-r <num>` | Rate limit. Maximum new input sessions initialized per second.
`-s <seconds>` | Periodically report progress statistics information.<br>Default: 10 s.
`-t <seconds>`<br>`--timeout <seconds>` | Maximum time spent waiting for a reply to a request previously sent (before retransmissing or giving up).<br>If set to 0, the program will never wait for a reply.<br>Default: 1 s.
`--retransmit <num>` | Maximum number of retransmissions (not including the first packet) of a given request to which no reply was received (before giving up).<br>Default: 2.
`-T` | Template mode.
`-v` | Print program version information.
`-x` | Turn on additional debugging. (`-xx` gives more debugging, up to `-xxxx`).
`-X` | Turn on FreeRADIUS libraries debugging (use this in conjunction with `-x`).


# Examples

Refer to [usage-examples.md](https://github.com/nchaigne/dhcperfcli/blob/master/doc/usage-examples.md).


# Performance testing

Refer to [performance-testing.md](https://github.com/nchaigne/dhcperfcli/blob/master/doc/performance-testing.md).


# Time-data statistics (InfluxDB, Grafana)

Refer to [time-data.adoc](doc/time-data.adoc) and [grafana.adoc](doc/grafana.adoc).

# Guide

## Input items

The program uses *input items* to build the DHCP packets.
An input item is a list of *attribute/value pairs* (or just *value pairs*) that are provided through standard input and/or a file. An attribute corresponds to an element of the DHCP packet (field or option).

An *value pair* is specified as follows:

`<attribute name> = <value>`

The name of DHCP attributes (along with their type, and enumerated values if applicable) are defined in FreeRADIUS DHCP dictionary files: [dhcpv4/dictionary.rfc2131](https://github.com/FreeRADIUS/freeradius-server/blob/master/share/dictionary/dhcpv4/dictionary.rfc2131) and [dhcpv4/dictionary.freeradius.internal](https://github.com/FreeRADIUS/freeradius-server/blob/master/share/dictionary/dhcpv4/dictionary.freeradius.internal).

For example:

```text
DHCP-Transaction-Id = 42
DHCP-Client-Hardware-Address = 50:41:4e:44:41:00
DHCP-Hostname = "myhost.whimsical.org"
DHCP-Message-Type = Discover
```

In this example, DHCP fields `xid` and `chaddr` are provided, as well as DHCP options 12 (Host Name) and 53 (DHCP Message Type).

You do not need to provide attributes for DHCP fields `op`, `htype`, `hlen`. These are set automatically.<br>
Field `xid` can be omitted, in which case the program will provide a value.<br>
The message type can also be provided through command line argument `<command>`. As a rule, values obtained from input items always take precedence over arguments.

Two input items are separated by an empty line.<br>
If the input is provided through stdin, this can be achieved with __`echo -e "\n\n"`__.

In addition to DHCP attributes, the program accepts a few control attributes in input items:


Attribute|Description
-|-
`Packet-Src-IP-Address` &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; | The packet source IP address. Automatically set if option `-g` is provided.
`Packet-Dst-IP-Address` | The packet destination IP address. Can also be set through argument `<server>`.
`Packet-Src-Port` | The packet source UDP port. Default is 68 for a client, 67 for a gateway.
`Packet-Dst-Port` | The packet destination UDP port. Default is 67 for a server or a gateway.
`DHCP-Gateway` * | Handle packets sent as if relayed through a gateway (`<gw>[:<port>]`).<br>Same as option `-g`, but for this input item only.<br>Can be provided multiple times, in which case packets will be sent using all of these gateways in a round-robin fashion.
`Input-Name` | Name of this item. Used in ongoing statistics, and as a prefix for named transactions shown in end report.
`Rate-Limit` | Maximum new sessions initialized per second from this input item.<br>Actual rate for a given item is calculated from the time it started being used.
`Start-Delay` | Delay (seconds) before allowing to use this input item to start new sessions.<br>This is useful to handle synchronization between multiple input items.
`Max-Duration` | Limit duration (seconds) for starting new sessions from this input item (relative to the time it started being used).<br>If a global limit is set (option `-L`), then the earliest limit applies.
`Max-Use` | Maximum number of sessions that can be initialized from this input item. (Same as option `-c` for this input item only.)
`Consecutive-Use` | Use this input item multiple times in a row. (The default is to use all input items in a round-robin fashion.)
`DHCP-Encoded-Data` | DHCP pre-encoded data. Refer to related section for details.
`DHCP-Authorized-Server` * | Authorized servers. Only allow replies from one of these.<br>Same as option `-a`, but for this input item only.<br>Can be provided multiple times, to authorize a list of servers.
`DHCP-Workflow-Type` | Workflow type: `DORA` (Discover, Offer, Request, Ack), `Dora-Decline` (DORA followed by Decline), `Dora-Release` (DORA followed by Release).<br>Takes precedence over `<command>` argument. Ignored if `DHCP-Message-Type` is provided.

Input items can be used more than once with option `-c`. All input items are used in the order in which they are provided. If they are reused this will also be in the same sequential order.


## Transaction Id

The Transaction Id (field `xid`) is a number used to correlate messages and responses between a client and a server. By default xid values are generated incrementally, starting with a random value (or option `-I`).

Once a reply is received to a message (or the timeout expires), the allocated xid is freed and might be used again.

For a given DHCP packet, a specific xid value can be requested (through input attribute `DHCP-Transaction-Id`), which *dhcperfcli* will try to allocate. If this is not possible (which means packets are sent in parallel and this xid is already in use) then it will fall back to the automatic incremental generation.

For a DORA transaction, the xid used to build the Request message is the same as from the Offer reply (which is also the same as the xid from the Discover message), as described in RFC 2131.


## Template and program termination

Template mode is enabled through option `-T`.

If not in template mode, each input item is used to build and send exactly one request (unless option `-c` is provided). The program can only start as many sessions as there are input items.

Conversely, in template mode, each input item can be used to build any number of requests. After reaching the last input item, the program loops back to the first one. Template mode is essential to running performance tests.

A single input item may actually be all you need. Variability between requests can be achieved through xlat expansion (see related section).

In template mode, the program will run indefinitely, unless you explicitly provide a limit, through:
- Option `-L` (maximum duration for starting new sessions).
- Option `-N` (number of sessions to start from input).
- Option `-c` (number of sessions to start from each input item).

Limits can also be set in each input item using control attributes.

You can also manually signal the program to end (by sending a SIGHUP, SIGINT, or SIGTERM):
- The first time one such signal is received, the program will stop starting new sessions. It will wait until ongoing sessions are gracefully terminated.
- If a second signal is received, then it will halt immediately. Remaining ongoing sessions will be forcefully terminated.

A SIGKILL signal (a.k.a « kill -9 ») will stop the program immediately, but won’t allow for the end report statistics to be displayed.


Example:

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.range:50:41:4e:44:41:00-50:41:4e:44:41:09}\""  |  dhcperfcli  -T -N 10 -g 10.11.12.1  10.11.12.42  discover
`__

This will generate and send (simulating a gateway with option `-g`) successively 10 DHCP Discover messages, using client MAC addresses `50:41:4e:44:41:00`, `50:41:4e:44:41:01` ... up to `50:41:4e:44:41:09`.


## Xlat expansion

Xlat expansion is a powerful mechanism through which variable input items attributes are dynamically expanded to a value, each time a new session is initialized from that item.
Xlat expansion is enabled:
- Automatically in template mode (option `-T`)
- Otherwise, explicitly through option `--xlat`

Xlat expansion, if enabled, is applied on a given attribute:
- If its value is enclosed within double quotes (`"..."`) - *single quotes will not work!*
- And contains the special xlat character `%` (at least once).

An xlat expression is specified through the construct `%{ ... }`. Several xlat expressions can be included in a single attribute.

The xlat character `%` can be escaped through a `%%`.

There are two categories of xlat expansion:
- Xlat attribute reference - through which an attribute can reference another (preceding) attribute.
- Xlat function - which allows to generate a value (which depends on the function used, and its parameters).

### Xlat attribute reference

Example:

```text
Tmp-Ethernet-0 = 50:41:4e:44:41:00
DHCP-Client-Hardware-Address = "%{Tmp-Ethernet-0}"
DHCP-Hostname = "host.%{Tmp-Ethernet-0}.whimsical.org"
```

This will expand field `chaddr` to `50:41:4e:44:41:00`, and DHCP option 12 (HostName) to `host.50:41:4e:44:41:00.whimsical.org`.

Here, `Tmp-Ethernet-0` is not directly used to encode the DHCP packet. It is merely a temporary attribute, whose sole purpose is to be referenced by other attributes.

Other such temporary attributes are available (defined in [freeradius/dictionary.freeradius.internal](https://github.com/FreeRADIUS/freeradius-server/blob/master/share/dictionary/freeradius/dictionary.freeradius.internal)):
- `Tmp-String-0` to `Tmp-String-9`
- `Tmp-Integer-0` to `Tmp-Integer-9`
- `Tmp-IP-Address-0` to `Tmp-IP-Address-9`
- `Tmp-Octets-0` to `Tmp-Octets-9`
- `Tmp-Ethernet-0` to `Tmp-Ethernet-4`

### Xlat functions

The following xlat functions are available:

Function|Description
-|-
`num.range` &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; | `"%{num.range:<lower value>-<upper value>}"`.<br><br>Generate incrementing values within a specified range of numbers (`<lower value>` and `<upper value>`). After reaching `<upper value>`, it will wrap around (reset to `<lower value>`).<br>`<lower value>` and `<upper value>` can be omitted (default : respectively, 0 and `UINT64_MAX`).<br><br>Example: `"%{num.range:0-65535}"`
`num.rand` | `"%{num.rand:<lower value>-<upper value>}"`<br><br>Similar to `num.range`, but with the numbers generated randomly in the specified range.
`ipaddr.range` | `"%{ipaddr.range:<lower value>-<upper value>}"`<br><br>Generate incrementing values within a specified range of IPv4 addresses (`<lower value>` and `<upper value>`). After reaching `<upper value>`, it will wrap around (reset to `<lower value>`).<br>`<lower value>` and `<upper value>` can be omitted (default : respectively, `0.0.0.1` and `255.255.255.254`).<br><br>Example: `"%{ipaddr.range:10.0.0.1-10.0.0.255}"`
`ipaddr.rand` | `"%{ipaddr.rand:<lower value>-<upper value>}"`<br><br>Similar to `ipaddr.range`, but with the IPv4 addresses generated randomly in the specified range.
`ethaddr.range` | `"%{ethaddr.range:<lower value>-<upper value>}"`<br><br>Generate incrementing values within a specified range of Ethernet addresses (`<lower value>` and `<upper value>`). After reaching `<upper value>`, it will wrap around (reset to `<lower value>`).<br>`<lower value>` and `<upper value>` can be omitted (default : respectively, `00:00:00:00:00:01` and `ff:ff:ff:ff:ff:fe`).<br><br>Example: `"%{ethaddr.range:50:41:4e:44:41:00-50:41:4e:44:41:09}"`
`ethaddr.rand` | `"%{ethaddr.rand:<lower value>-<upper value>}"`<br><br>Similar to `ethaddr.range`, but with the Ethernet addresses generated randomly in the specified range.
`randstr` | `"%{randstr:<char sequence>}"`<br><br>Generate a random string from a sequence of character classes. This is mostly equivalent to the FreeRADIUS xlat function of the same name.<br>Each character in `<char sequence>` is substituted with a random character from the corresponding class:<br>`c` = lowercase letters - `[a-z]`.<br>`C` = uppercase letters - `[A-Z]`.<br>`n` = digits - `[0-9]`.<br>`a` = alphanumeric - `[a-zA-Z0-9]`<br>`!` (exclamation mark) or `,` (comma) = punctuation.<br>`.` (dot) = alphanumeric + punctuation.<br>`s` = alphanumeric + salt characters `[./]`.<br>`o` = alphanumeric excluding easily confused characters - `[469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz]`.<br>`b` = binary data.<br>(space) = space.<br><br>Example: `"%{randstr:Cc12na ,.so}"`


Xlat expressions can contain nested functions. For example:<br>
`"%{randstr:%{num.rand:3-42}C}"`

## DHCP pre-encoded data

Instead of letting the program encode your DHCP packet, you can do it yourself. This is achieved through a special control attribute: `DHCP-Encoded-Data`.<br>
If provided, all DHCP value pairs are ignored. The command `argument` should be omitted (it is ignored). Other control attributes (such as `Packet-Src-IP-Address`) can be provided.

This has several purposes:
- You can extract the content of a real DHCP packet from a network capture, for example using Wireshark (select a packet, right click on "Bootstrap Protocol" / "Copy" / "... as a Hex Stream"), then feed it (altered or not) to *dhcperfcli*.

- You can create purposely malformed data. This allows to see how the DHCP server behaves when handling such a packet.

For example:

>__`
echo "DHCP-Encoded-Data=0x0101060100000001000000000000000000000000000000000000000050414e444100"  |  dhcperfcli  -i eth0 -P 3  255.255.255.255
`__

This is obviously malformed data: it ends right after the first 6 octets of field `chaddr` (the client MAC address).
You can send it, but you won't get a reply from any sane DHCP server (for that you need to provide at least option 53 *Message Type*). Actually, the program won't even wait for a reply (because it doesn't think one is expected).

Another example:
>__`
echo "DHCP-Encoded-Data=0x0101060100000001000000000000000000000000000000000000000050414e4441000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101ff"  |  dhcperfcli  -i eth0 -P 3  255.255.255.255
`__

This one is a well-formed (if a bit hard to read, but option `-P 3` will display something more accessible) DHCP Discover packet, to which you can get a DHCP Offer reply.


## Statistics

### End report

During its execution, *dhcperfcli* collects a set of DHCP related metrics, which it will display at the end before exiting.

For example:
```
*** Statistics (global):
        Elapsed time (s)    : 0.002
        Sessions            : 1
        Packets sent        : 3 (Discover: 1, Request: 1, Decline: 1)
        Packets received    : 2 (Offer: 1, Ack: 1)
        Retransmissions     : 1
        Packets lost        : 0
        Replies unexpected  : 0
*** Statistics (per-transaction):
        (All)          :  num: 2, RTT (ms): [avg: 0.410, min: 0.366, max: 0.454]
        Discover:Offer :  num: 1, RTT (ms): [avg: 0.454, min: 0.454, max: 0.454]
        Request:Ack    :  num: 1, RTT (ms): [avg: 0.366, min: 0.366, max: 0.366]
        <DORA>         :  num: 1, RTT (ms): [avg: 1.480, min: 1.480, max: 1.480]
```

This shows the following information:
- Global statistics
  - Total duration of the test, in seconds.
  - Number of sessions played out.
  - Number of packets sent (as a whole and broken down by message type).<br>Note: this does not include retransmissions.
  - Number of packets received (as a whole and broken down by message type).
  - Number of retransmissions (if any).
  - Number of requests for which no response was received (in the allowed time limit).
  - Number of unexpected replies.<br>This may be responses received after the allowed time limit, or which we cannot correlate with a request (giaddr / source IP address mixup, transaction Id mismatch, or other odd things that broken DHCP servers might do).

- Per-transaction statistics
  - For each transaction type (composed of request type, reply type, and optional prefix):
    - Number of such transactions.
    - RTT (average, min and max response times).
    - Average transaction rate per second (if the test lasts at least one second).
  - Likewise, for DORA workflows (if there are some).
  - And `(All)` shows the aggregation of all transactions types (if there are more than one).

Notes:

- Some requests (such as DHCP Release) do not get a response, and thus will never be part of a transaction.

- RTT (*round trip time*) is the time interval between a packet being sent and the reception of the corresponding response. This is an accurate measurement of how fast the DHCP server can handle a message. For DORA workflows, this includes the time spent decoding and encoding packets, so this is more than the sum of Discover / Offer and Request / Ack RTT.

### Ongoing statistics

In addition to the end report, an ongoing statistics summary can also be displayed at regular time interval (option `-s`) during a performance test. This provides real-time information about what's going on.

For example:

```
(*) 17:42:55 t(30.000) (50.0%) sessions: [started: 30000 (25.0%), ongoing: 0], session rate (/s): 999.990
```

This shows the following information:
- Current absolute local time.
- Current elapsed time of the test, in seconds.
- If the test is time-limited (option `-L`), completed percentage of said limit.
- Number of sessions started.
- If the test is session-limited (option `-N`), completed percentage of said limit.
- Number of ongoing sessions (requests expecting a reply).
- Rate of all sessions started per second (average calculated from the beginning of the test).

In addition, the following information is displayed if relevant:
- Number of lost packets (for which a reply was expected, but we didn't get one).
- Number of NAK replies.

For example (unresponsive server):

```
(*) 17:42:55 t(5.001) (50.0%) sessions: [in: 320, ongoing: 64, lost: 256], session rate (/s): 63.987
```

If multiple input items are involved, a second line provides additional, per-input statistics, which shows:
- The input item status (`W` = waiting, `A` = active, `T` = terminated).
- The rate per second of sessions started from this input item over its lifespan.


```
(*) 17:42:55 t(9.000) (60.0%) sessions: [in: 1806, ongoing: 0], session rate (/s): 100.335
 └─ per-input rate (/s): #0 (A): 100.334, #1 (T): 200.665, #2 (W)
```


## Displaying DHCP packets

DHCP packets sent or received can be printed on standard output. The level of detail is controled through option `-P`. If omitted, a default is figured out according to number of packets and parallelism.

### Trace packet header

Packet header is a one-line summary traced with option `-P 1` (or higher).<br>
Example:

>`
(0) Sent Discover (hwaddr: 50:41:4e:44:41:00) Id 1001 (0x000003e9) from 0.0.0.0:68 to 255.255.255.255:67 via eth0 length 300
`

>`
(0) Received Offer (hwaddr: 50:41:4e:44:41:00, yiaddr: 16.128.0.1) Id 1001 (0x000003e9) from 10.11.12.42:67 to 16.128.0.1:68 via eth0 length 308
`

This shows the following information:
- The session number: `(0)`. This is a unique number for the execution of *dhcperfcli*, starting at 0 and incremented for each new session started.
- Whether the packet is `Sent` (by the program) or `Received` (from a DHCP server or relay).
- The message type, such as `Discover` or `Offer`.
- Key DHCP information extracted from the packet: `hwaddr`, `yiaddr`.
- The Transaction Id (`xid`): `Id 1001 (0x000003e9)`.
- The packet source and destination (IP address and port): `from 0.0.0.0:68 to 255.255.255.255:67`.
- The network interface (if it can be figured out): `via eth0`.
- The length of the DHCP data: `length 300`.


### Trace value pair attributes

Value pair attributes are traced with option `-P 2` (or higher).<br>
For requests, this is the input from which the packet is built. For responses, this is the decoded data.

Example:
```
DHCP vps fields:
        DHCP-Client-Hardware-Address = 50:41:4e:44:41:00
        DHCP-Transaction-Id = 1001
DHCP vps options:
        (12) DHCP-Hostname = "dhcperfcli"
        (51) DHCP-IP-Address-Lease-Time = 86400
```

The names of DHCP attributes are defined in FreeRADIUS DHCP dictionary files: [dhcpv4/dictionary.rfc2131](https://github.com/FreeRADIUS/freeradius-server/blob/master/share/dictionary/dhcpv4/dictionary.rfc2131) and [dhcpv4/dictionary.freeradius.internal](https://github.com/FreeRADIUS/freeradius-server/blob/master/share/dictionary/dhcpv4/dictionary.freeradius.internal).<br>
Displayed values are formatted according to the attribute type. For an option, its number is printed in brackets.


### Trace encoded hex data

Encoded data is traced as hex values with option `-P 3` (or higher).<br>
This displays the actual content of the DHCP packet, broken down by fields and options for readability (similar to what you might view with a tool such as Wireshark).

Example:
```
DHCP hex data:
  0000          op: 01
  0001       htype: 01
  0002        hlen: 06
  0003        hops: 00
  0004         xid: 00 00 03 e9
  0008        secs: 00 00
  000a       flags: 00 00
  000c      ciaddr: 00 00 00 00
  0010      yiaddr: 00 00 00 00
  0014      siaddr: 00 00 00 00
  0018      giaddr: 00 00 00 00
  001c      chaddr: 50 41 4e 44 41 00 00 00 00 00 00 00 00 00 00 00
  002c       sname: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  006c        file: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  00ec     options: 63 82 53 63
  00f0          53: 35 01 01
  00f3          51: 33 04 00 01 51 80
  00f9          12: 0c 0a 64 68 63 70 65 72 66 63 6c 69
  0105         end: ff
  0106         pad: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00
```


### Malformed packet trace example

This is the trace obtained with option `-P 3` for the malformed packet example shown earlier:
```
(0) Sent malformed packet (hwaddr: 50:41:4e:44:41:00) Id 1 (0x00000001) from 0.0.0.0:68 to 255.255.255.255:67
via eth0 length 34
DHCP data:
        DHCP-Encoded-Data = 0x0101060100000001000000000000000000000000000000000000000050414e444100
DHCP hex data:
  0000          op: 01
  0001       htype: 01
  0002        hlen: 06
  0003        hops: 01
  0004         xid: 00 00 00 01
  0008        secs: 00 00
  000a       flags: 00 00
  000c      ciaddr: 00 00 00 00
  0010      yiaddr: 00 00 00 00
  0014      siaddr: 00 00 00 00
  0018      giaddr: 00 00 00 00
  incomplete/malformed DHCP data (len: 34)
  001c   remainder: 50 41 4e 44 41 00
```
