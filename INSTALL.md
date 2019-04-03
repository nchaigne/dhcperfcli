
# Installation

## Prerequisites

Building *dhcperfcli* requires recent sources of FreeRADIUS version 4.0.x (`master` branch). Note that this version is currently in development. It's alright. We're using FreeRADIUS libraries. They just work fine.

That said, changes made by the FreeRADIUS team may break *dhcperfcli* at any time. Although I try to keep up with these changes, I cannot guarantee responsiveness. Consequently, it is recommended to build a specific FreeRADIUS commit (with which *dhcpercli* will work) rather than the HEAD: [d8bff6f3b3c128583704345623f5f253d4d87836](https://github.com/FreeRADIUS/freeradius-server/tree/d8bff6f3b3c128583704345623f5f253d4d87836) (April 3, 2019).

Instructions on how to build FreeRADIUS is available on their wiki :
https://wiki.freeradius.org/building/home

To sum up you will need :

- C11 support. This implies a relatively recent compiler (GCC 4.9.0 or later). Version of GCC shipped with RHEL 7 is not adequate, so an upgrade (e.g. [GCC 7.3.0](https://gist.github.com/nchaigne/9eba78dafb011b138fa513ea5fd016a8)) is necessary.<br>Alternatively, you can compile with clang (3.0 or later).

- Talloc

>__`yum -y install libtalloc-devel`__

- Libkqueue

  - Build from sources:

>__`LIBKQUEUE_VERSION=2.1.0`__<br>
>__`cd /home/build`__<br>
>__`wget https://github.com/mheily/libkqueue/archive/v${LIBKQUEUE_VERSION}.tar.gz`__<br>
>__`tar -xvzf v${LIBKQUEUE_VERSION}.tar.gz`__<br>
>__`cd libkqueue-${LIBKQUEUE_VERSION}`__<br>
>__`./configure --prefix=/opt/libkqueue/${LIBKQUEUE_VERSION}`__<br>
>__`make && make install`__<br>


And optionally:

- Libpcap

>__`yum -y install libpcap-devel`__

While libpcap is not mandatory to build, it is needed by *dhcpercli* to send packets directly through the data link layer (Ethernet). You need this to simulate broadcasting directly connected clients (i.e. not relayed) with no assigned IP address.


## Build FreeRADIUS

### Get the sources

You can get FreeRADIUS sources using git as follows:
>__`git clone https://github.com/FreeRADIUS/freeradius-server.git`__<br>
>__`cd freeradius-server`__<br>
>__`git checkout master`__

Avoid cloning using GitHub Desktop on Windows. You may have issues with line endings. And... other bad things. I've been there. Windows is hell.

Alternatively, you can do without git. Download a zip file of the sources from GitHub (select "Clone or download", then "download ZIP"):
https://github.com/FreeRADIUS/freeradius-server

Then:
>__`unzip freeradius-server-master.zip`__<br>
>__`cd freeradius-server-master`__

### Build from sources

>__`./configure --disable-developer --prefix=/opt/freeradius/4.0.x \`__<br>
>__`--with-kqueue-include-dir=/opt/libkqueue/2.1.0/include/kqueue \`__<br>
>__`--with-kqueue-lib-dir=/opt/libkqueue/2.1.0/lib`__<br>
>__`make`__<br>
>__`make install`__<br>

Notes:
- Do __*not*__ configure with `--enable-developer`. This is not appropriate for performance tests. The CPU cost is simply too high.
- Set `--prefix` (or not) according to where you want FreeRADIUS to be installed. As this is a version currently in development I recommand not to use the default.


## Build *dhcperfcli*

### Get the sources

In the same way as for FreeRADIUS, you can get *dhcperfcli* sources either by cloning with git or downloading them from GitHub.
>__`git clone https://github.com/nchaigne/dhcperfcli.git`__<br>
>__`cd dhcperfcli`__

Or download a zip file of the sources from GitHub:
https://github.com/nchaigne/dhcperfcli

Then:

>__`unzip dhcperfcli-master.zip`__<br>
>__`cd dhcperfcli-master`__

### Build from sources

Copy *dhcpercli* files into FreeRADIUS source tree:

>__`cp -f src/modules/proto_dhcpv4/* <FreeRADIUS sources>/src/modules/proto_dhcpv4/`__<br>
>__`cp -Rf share/dictionary/dhcperfcli <FreeRADIUS sources>/share/dictionary/`__<br>

Note: file `all.mk` will be overwritten. This is necessary so FreeRADIUS knows that it has to build *dhcperfcli*.

Then build FreeRADIUS again:
>__`make`__<br>
>__`make install`__

### Update PATH

You will need to update your PATH environment variable so you can execute the program from wherever.<br>
For example:
>__`export PATH=/opt/freeradius/4.0.x/sbin:$PATH`__

Finally, check installation:

>__`dhcperfcli -v`__

All set!
