
# Usage examples


## Discover (client broadcast)

A client with no configured IP address broadcasts a DHCP Discover message on its local interface.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The DHCP message type (option 53 *Message Type*, provided through argument `discover`).

DHCP fields `op`, `htype`, `hlen` are automatically set by the program.<br>
Additional DHCP fields or options can be provided. For example, clients often provide a Client Identifier option in addition to their MAC address.

There is no source IP address. Source port is 68 (default for a client).<br>
Packet destination is broadcast IP address (255.255.255.255) and MAC address (set implicitly), port 67 (default for a server).

The program will wait for the first suitable DHCP Offer reply sent by a DHCP server on the chosen interface (option `-i`), up to a maximum wait time (option `-t`).

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -i eth0 -t 1.5  255.255.255.255  discover
`__

Note: multiple DHCP servers may provide an Offer. Option `-A` allows to wait for all replies (up to the timeout limit). The default behavior is to stop waiting as soon as a valid Offer reply is received.

Alternatively, option `-a` allows to only consider a reply coming from a specific server (which you have to know beforehand).



## Discover (gateway)

A gateway (DHCP relay or concentrator) unicasts a DHCP Discover message to a DHCP server.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The DHCP message type (option 53 *Message Type*, provided through argument `discover`).
- The gateway IP address (field `giaddr`), here provided through option `-g`.

Additional DHCP fields or options can be provided. For example, here field `xid` is set to 362 (the default is 0).

Packet source is the gateway IP address, port 67 (default for a gateway).<br>
Packet destination is the DHCP server IP address, port 67 (default for a server).

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00, DHCP-Transaction-Id=362"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  discover
`__

Without option `-g`, the same behavior can be obtained as follows:

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00, DHCP-Transaction-Id=362, Packet-Src-IP-Address=10.11.12.1, Packet-Src-Port=67, DHCP-Gateway-IP-Address=10.11.12.1"  |  dhcperfcli  10.11.12.42  discover
`__

Note that field `giaddr` and the packet source IP address have the same value. The DHCP server will respond to `giaddr` if it is set, so the program must be listening on that address.


## Request (SELECTING state, client broadcast)

A client with no configured IP address broadcasts a DHCP Request message on its local interface, in order to allocate the address proposed by a DHCP server in the DHCP Offer reply.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The requested IP address (option 50 *Requested IP address*), which has been obtained from the DHCP Offer reply in field `yiaddr`.
- The address of the DHCP server (option 54 *Server Identifier*). This indicates that the client is responding to a DHCP Offer reply.
- The DHCP message type (option 53 *Message Type*, provided through argument `request`).

Note: field `ciaddr` must be zero (the client does not have an assigned IP address yet).

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00, DHCP-Requested-IP-Address=16.128.0.1, DHCP-DHCP-Server-Identifier=10.11.12.42"  |  dhcperfcli  -i eth0  255.255.255.255  request
`__


## Request (SELECTING state, gateway)

On behalf of a client in SELECTING state, a gateway (DHCP relay or concentrator) unicasts a DHCP Request message to a DHCP server.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The requested IP address (option 50 *Requested IP address*), which has been obtained from the DHCP Offer reply in field `yiaddr`.
- The address of the DHCP server (option 54 *Server Identifier*). This indicates that the client is responding to a DHCP Offer reply.
- The DHCP message type (option 53 *Message Type*, provided through argument `request`).
- The gateway IP address (field `giaddr`), here provided through option `-g`.

Note: field `ciaddr` must be zero (the client does not have an assigned IP address yet).

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00, DHCP-Requested-IP-Address=16.128.0.1, DHCP-DHCP-Server-Identifier=10.11.12.42"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  request
`__


## DORA

A DORA transaction (acronym for *Discover, Offer, Request, Ack*) is the succession of two DHCP exchanges which allow a client to obtain a lease:
- A Discover, to which the server responds with an Offer,
- Followed by a Request, to which the server responds with an Ack.

Performing a DORA requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The workflow type, provided through argument `dora`.

In this case you do not provide the message type. It will be set automatically by the program (Discover for the first message, Request for the second).

The input item can contain other attributes which will be used to build the Discover and Request messages.

You should not provide options 50 (*Requested IP address*) and 54 (*Server Identifier*). These will be set automatically in the Request packet from information provided by the server in the Offer reply.

Example of DORA from a broadcasting client:

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -i eth0  255.255.255.255  dora
`__

Example of DORA using a gateway:

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -g 10.11.12.1   10.11.12.42  dora
`__
