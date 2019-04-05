
# Performance testing and benchmarking

## Principles

Performance testing aims at monitoring how a DHCP server behaves when dealing with sustained sollicitation. This can involve the following interrogations:
- How many requests can the server handle per second? how many leases can it serve per second?
- What are the response times and how do they shift depending on the server sollicitation? on the number of allocated leases?
- What are the server capabilites, as compared to other servers? as compared to another version of the same server? as compared to the same server with a different configuration?
- What resources does the server consume? (CPU, RAM, disk usage, I/O...)
- Is the server stable over time?

*dhcperfcli* can help you answer these questions by simulating extensive DHCP traffic from many different clients.

Several options are of interest:
- Option `-T` (template mode) is almost indispensable. Performance testing requires to send many packets, and providing input for each of them is not really practical (although you can, if you really want to).
- Options `-L` and `-N` allow to specify when the test should end (in term of duration, and number of sessions, respectively).
If you do not set a limit, the test will go on indefinitely, until you signal the program to stop (`SIGHUP`, `SIGINT` or `SIGTERM`).
- Option `-p` allows to send that many packets in parallel. (The default is to send them sequentially - which would not stress much even the worst of DHCP servers).<br>
To determine a suitable value you have to consider if your server is multi-threaded or not. Or... just set an arbitrary high value. *dhcperfcli* will be happy to comply.
- Option `-r` tells the program to limit to a target value the rate of packets sent per second.
If omitted, the limit will be the capabilites of the server (assuming an adequate level of parallelism is set with option `-p`).
- Option `-a` allows to ignore Offer replies that do not originate from the server being tested (useful for broadcasting tests).

Xlat expansion (automatically enabled in template mode) allows to dynamically expand input items and generate unique values for each DHCP request.


**Warning:** you must be duly authorized to carry out performance tests on a DHCP server. Please be careful, in particular if you're broadcasting: you may reach servers that you're not aware of.


## Examples

- A test which lasts for 60 seconds, simulating a gateway sending DHCP Discover messages (and expecting Offer replies) concurrently, at a fixed rate of 1000 packets per second. Each packet originates from a distinct client (with incrementing client MAC addresses, starting from `50:41:4e:44:41:00`, and a randomly generated client hostname).

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.range:50:41:4e:44:41:00}\", DHCP-Hostname=\"%{randstr:12c3n}.whimsical.org\""  |  dhcperfcli  -T -L 60 -p 32 -r 1000 -g 10.11.12.1  10.11.12.42  discover
`__


- A test which lasts until 20k packets have been sent, broadcasting DHCP Discover messages concurrently, at a fixed rate of 1000 packets per second. Each packet originates from a distinct client (with randomly selected client MAC addresses).

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.rand}\""  |  dhcperfcli  -T -N 20000 -p 32 -r 1000 -i eth0  255.255.255.255  discover
`__


- A ten minutes long test with no rate limit, sending DHCP Discover messages as fast as the server can handle them (allowing to measure its capabilities).

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.range:50:41:4e:44:41:00}\""  |  dhcperfcli  -T -L 600 -p 32 -g 10.11.12.1  10.11.12.42  discover
`__


- The same test but this time playing out DORA transactions. With these, the server will really allocate IP addresses. Since we're not releasing them, you should have sufficiently large subnets configured (and an appropriate lease expiration delay) - that is, if you do not wish to run out of available leases.

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.range:50:41:4e:44:41:00}\""  |  dhcperfcli  -T -L 600 -p 32 -g 10.11.12.1  10.11.12.42  dora
`__


- To avoid having to worry about leases depletion, you can instead use a DORA / Release workflow. This is more considerate to the server (but involves an additional DHCP Release message for each session - more work!).

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.range:50:41:4e:44:41:00}\""  |  dhcperfcli  -T -L 600 -p 32 -g 10.11.12.1  10.11.12.42  dorarel
`__


- Or if you want to be really mean, you can acquire leases and decline them, prompting the server to mark them as unavailable. If sustained long enough, this will deplete the entire IP address pool managed by the server (a.k.a. *DHCP starvation attack*).

>__`
echo "DHCP-Client-Hardware-Address=\"%{ethaddr.range:50:41:4e:44:41:00}\""  |  dhcperfcli  -T -p 32 -i eth0  255.255.255.255  dorarec
`__
