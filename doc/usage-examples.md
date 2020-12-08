
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
echo "Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -i eth0 -t 1.5  255.255.255.255  discover
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
echo "Client-Hardware-Address=50:41:4e:44:41:00, Transaction-Id=362"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  discover
`__

Without option `-g`, the same behavior can be obtained as follows:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Transaction-Id=362, Gateway-IP-Address=10.11.12.1, Packet-Src-IP-Address=10.11.12.1, Packet-Src-Port=67"  |  dhcperfcli  10.11.12.42  discover
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
echo "Client-Hardware-Address=50:41:4e:44:41:00, Requested-IP-Address=16.128.0.1, Server-Identifier=10.11.12.42"  |  dhcperfcli  -i eth0  255.255.255.255  request
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
echo "Client-Hardware-Address=50:41:4e:44:41:00, Requested-IP-Address=16.128.0.1, Server-Identifier=10.11.12.42"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  request
`__


## Request (INIT-REBOOT state, client broadcast)

A client, which has knowledge of an IP address previously leased to him, comes back online after a reboot or network restart. This client broadcasts a DHCP Request message on its local interface, in order to verify his previous IP address.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The requested IP address (option 50 *Requested IP address*).
- The DHCP message type (option 53 *Message Type*, provided through argument `request`).

Notes:
- Field `ciaddr` must be zero (the client does not have an assigned IP address yet).
- Option 54 *Server Identifier* must not be set (the client is not responding to a DHCP Offer).

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Requested-IP-Address=16.128.0.1"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  request
`__


## Request (INIT-REBOOT state, gateway)

On behalf of a client in INIT-REBOOT state, a gateway (DHCP relay or concentrator) unicasts a DHCP Request message to a DHCP server.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The requested IP address (option 50 *Requested IP address*).
- The DHCP message type (option 53 *Message Type*, provided through argument `request`).
- The gateway IP address (field `giaddr`), here provided through option `-g`.

Notes:
- Field `ciaddr` must be zero (the client does not have an assigned IP address yet).
- Option 54 *Server Identifier* must not be set (the client is not responding to a DHCP Offer).

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Requested-IP-Address=16.128.0.1"  |  dhcperfcli  -i eth0  255.255.255.255  request
`__


## DORA

A DORA transaction (acronym for *Discover, Offer, Request, Ack*) is the succession of two DHCP exchanges which allow a client to obtain a lease:
- A DHCP Discover, to which the server responds with a DHCP Offer,
- Followed by a DHCP Request, to which the server responds with a DHCP Ack.

You can, of course, carry out a DORA workflow manually, by successively building and sending a DHCP Discover then a DHCP Request. Automating this sequence is merely a convenience offered by *dhcperfcli*.

Performing a DORA requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The workflow type, provided through argument `dora`.

In this case you do not provide the message type. It will be set automatically by the program (Discover for the first message, Request for the second).

The input item can contain other attributes which will be used to build the Discover and Request messages.

You can provide option 50 (*Requested IP address*), in which case it will be set in the Discover message. However, you may not be offered this IP address (if it was not available). In any case, the *Requested IP address* set in the Request message will be the value of field `yiaddr` from the Offer reply.

Example of DORA from a broadcasting client:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -i eth0  255.255.255.255  dora
`__

Example of DORA using a gateway:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -g 10.11.12.1   10.11.12.42  dora
`__

Note: if broadcasting, option `-A` has no effect, as the first valid Offer reply will be selected. However, option `-a` can be used to ignore all DHCP servers but one.


## DORA / Release

This is a DORA workflow, followed by an immediate DHCP Release.

This is not something that would happen in real life (after acquiring an IP address, a client will want to use it before relinquishing it). However, this is useful for testing purposes. This allows to gracefully inform the server that we do not need this address after all, so it can be freed and assigned to someone else if needed.

Performing a DORA / Release requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The workflow type, provided through argument `dorarel`.

Example of DORA / Release from a broadcasting client:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -i eth0  255.255.255.255  dorarel
`__

Example of DORA / Release using a gateway:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  dorarel
`__


## Request (RENEWING)

A client, which has a configured IP address, wishes to extend its lease before it expires. To do so, the client unicasts a DHCP Request message to the DHCP server.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The client IP address (field `ciaddr`).
- The DHCP message type (option 53 *Messsage Type*, provided through argument `request`).

Notes:
- Option 50 *Requested IP address* must not be set
- Option 54 *Server Identifier* must not be set (the client is not responding to a DHCP Offer).

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Client-IP-Address=16.128.0.1, Packet-Src-IP-Address=16.128.0.1"  |  dhcperfcli  10.11.12.42  request
`__

Or, if a gateway is involved:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Client-IP-Address=16.128.0.1"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  request
`__


## Decline

After being assigned an IP address, a client checks that this address is not already in use. If it is, the client broadcasts a DHCP Decline message.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The declined (already in use) IP address (option 50 *Requested IP address*).
- The DHCP message type (option 53 *Messsage Type*, provided through argument `decline`).
- The address of the DHCP server (option 54 *Server Identifier*).

Note: field `ciaddr` must be zero.

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Server-Identifier=10.11.12.42, Requested-IP-Address=16.128.0.1"  |  dhcperfcli  -i eth0  255.255.255.255  decline
`__

Or, if a gateway is involved:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Server-Identifier=10.11.12.42, Requested-IP-Address=16.128.0.1"  |  dhcperfcli  -g 10.11.12.1  10.11.12.42  decline
`__


## Release

A client, which has a configured IP address, is about to relinquish its lease on this address, and before doing so explicitly notifies the DHCP server.<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The client IP address (field `ciaddr`).
- The DHCP message type (option 53 *Messsage Type*, provided through argument `release`).
- The address of the DHCP server (option 54 *Server Identifier*).

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Server-Identifier=10.11.12.42, Client-IP-Address=16.128.0.1, Packet-Src-IP-Address=16.128.0.1"  |  dhcperfcli  10.11.12.42  release
`__

Or, if a gateway is involved:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Server-Identifier=10.11.12.42, Client-IP-Address=16.128.0.1"  |  dhcperfcli  -g 10.11.12.1 10.11.12.42  release
`__

Notes:
- Sending a DHCP Release is optional. Clients are often unable to do so, which means the server is in charge of dealing with expired leases.
- There is no response to a DHCP Release, so the program will not wait for one.


## Inform

A client which has a configured IP address wishes to obtain parameters from the DHCP server (for example, site specific option 252 *WPAD* for handling Web Proxy Auto-Discovery).<br>
This requires the following information:
- The client hardware (MAC) address (field `chaddr`).
- The client IP address (field `ciaddr`).
- The DHCP message type (option 53 *Messsage Type*, provided through argument `inform`).

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Client-IP-Address=16.128.0.1, Parameter-Request-List=252, Packet-Src-IP-Address=16.128.0.1"  |  dhcperfcli  10.11.12.42  inform
`__


Or, if a gateway is involved:

>__`
echo "Client-Hardware-Address=50:41:4e:44:41:00, Client-IP-Address=16.128.0.1, Parameter-Request-List=252"  |  dhcperfcli  -g 10.11.12.1 10.11.12.42  inform
`__

Note: the DHCP server responds directly to the client IP address (field `ciaddr`) even if the DHCP Inform is relayed. This entails that the client address must be reachable by the server (otherwise the client will never receive the DHCP Ack response). The program assumes this is the case.
