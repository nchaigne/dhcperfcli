
# Performance testing

Performance testing aims at monitoring how a DHCP server behaves when dealing with sustained sollicitation. This can involve the following interrogations:
- How many requests can the server handle per second? how many leases can it serve per second?
- What are the response times and how do they shift depending on the server sollicitation? on the number of allocated leases?
- What are the server capabilites, as compared to other servers? as compared to another version of the same server? as compared to the same server with a different configuration?
- What resources does the server consume? (CPU, RAM, disk usage, I/O...)
- Is the server stable over time?

*dhcperfcli* can help you answering these questions by simulating extensive DHCP traffic from many different clients.

Several options are of interest:
- Option `-T` (template mode) is almost indispensable. Performance testing requires to send many packets, and providing input for each of them is not really practical (although you can, if you really want to).
- Options `-L` and `-N` allow to specify when the test should end (in term of duration, and number of sessions, respectively). If you do not set a limit, the test will go on indefinitely, until you signal the program to stop (`SIGHUP`, `SIGINT` or `SIGTERM`).
- Option `-p` allows to send that many packets in parallel. (The default is to send them sequentially - which would not stress much even the worst of DHCP servers)
- Option `-r` tells the program to limit to a target value the rate of packets sent per second. If omitted, the limit will be the capabilites of the server (assuming an adequate level of parallelism is set with option `-p`).

Example:

>__`
echo "DHCP-Client-Hardware-Address=50:41:4e:44:41:00"  |  dhcperfcli  -T -L 60 -p 32 -r 1000 -g 10.11.12.1  10.11.12.42  discover
`__
