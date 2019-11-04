
# Installation

## Prerequisites

Building *dhcperfcli* requires recent sources of FreeRADIUS version 4.0.x (`master` branch). Note that this version is currently in development. It's alright. We're using FreeRADIUS libraries. They just work fine.

That said, changes made by the FreeRADIUS team may break *dhcperfcli* at any time. Although I try to keep up with these changes, I cannot guarantee responsiveness. Consequently, it is recommended to build a specific FreeRADIUS commit (with which *dhcpercli* will work) rather than the HEAD: [3b7b2c53adb449dabaa3b88cbc3ef00f89debabc](https://github.com/FreeRADIUS/freeradius-server/tree/3b7b2c53adb449dabaa3b88cbc3ef00f89debabc) (November 4, 2019).

Instructions on how to build FreeRADIUS is available on their wiki :
https://wiki.freeradius.org/building/home

To sum up you will need :

- C11 support. This implies a relatively recent compiler (GCC 4.9.0 or later). Version of GCC shipped with RHEL 7 is not adequate, so an upgrade (e.g. [GCC 9.2.0](https://gist.github.com/nchaigne/ad06bc867f911a3c0d32939f1e930a11)) is necessary.<br>Alternatively, you can compile with clang (3.0 or later).

- Talloc

>__`yum -y install libtalloc-devel`__

- Libkqueue

  - Build from sources (requires [cmake](https://cmake.org/download/) version 3):

>__`LIBKQUEUE_VERSION=2.3.1`__<br>
>__`cd /home/build`__<br>
>__`wget https://github.com/mheily/libkqueue/archive/v${LIBKQUEUE_VERSION}.tar.gz`__<br>
>__`tar -xvzf v${LIBKQUEUE_VERSION}.tar.gz`__<br>
>__`cd libkqueue-${LIBKQUEUE_VERSION}`__<br>
>__`cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/opt/libkqueue/${LIBKQUEUE_VERSION} -DCMAKE_INSTALL_LIBDIR=lib .`__<br>
>__`make && make install`__<br>


And optionally:

- Libpcap

>__`yum -y install libpcap-devel`__

While libpcap is not mandatory to build, it is needed by *dhcpercli* to send packets directly through the data link layer (Ethernet). You need this to simulate broadcasting directly connected clients (i.e. not relayed) with no assigned IP address.


## Build FreeRADIUS

### Get the sources

You can get FreeRADIUS sources using git as follows:
>__`git clone -n https://github.com/FreeRADIUS/freeradius-server.git`__<br>
>__`cd freeradius-server`__<br>
>__`git checkout master`__

Note: to check out a specific commit (as recommended), replace `master` with the commit ID. For example:

>__`git checkout 3b7b2c53adb449dabaa3b88cbc3ef00f89debabc`__

Avoid cloning using GitHub Desktop on Windows. You may have issues with line endings. And... other bad things. I've been there. Windows is hell.

Alternatively, you can do without git. Download a zip file of the sources from GitHub (select "Clone or download", then "download ZIP"):
https://github.com/FreeRADIUS/freeradius-server

Then:
>__`unzip freeradius-server-master.zip`__<br>
>__`cd freeradius-server-master`__

Note: if downloading a specific commit (as recommended), `master` will be replaced with the commit ID. Adjust as needed.

### Build from sources

Note: before proceeding, copy *dhcperfcli* files into FreeRADIUS source tree (see below), so that everything is built all at once.

>__`./configure --with-modules="rlm_dhcperfcli" \`__<br>
>__`--disable-developer --prefix=/opt/freeradius/4.0.x \`__<br>
>__`--with-kqueue-include-dir=/opt/libkqueue/2.3.1/include/kqueue \`__<br>
>__`--with-kqueue-lib-dir=/opt/libkqueue/2.3.1/lib`__<br>
>__`make`__<br>
>__`make install`__<br>

Notes:
- Do __*not*__ configure with `--enable-developer`. This is not appropriate for performance tests. The CPU cost is simply too high.
- Set `--prefix` (or not) according to where you want FreeRADIUS to be installed. As this is a version currently in development I recommand not to use the default.
- Option `--with-modules` is required to have FreeRADIUS run autoconf on *dhcperfcli* source directory (by default, it does so only on modules marked as "stable").


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

>__`cp -Rf src/modules/rlm_dhcperfcli/ <FreeRADIUS sources>/src/modules/`__<br>
>__`cp -Rf share/dictionary/dhcperfcli <FreeRADIUS sources>/share/dictionary/`__<br>

It is also necessary to add `dhcperfcli` to the `PROTOCOLS` list in FreeRADIUS Makefile (so that the dictionaries are included during install). This can be achieved as follows:

>__`sed -i '/^PROTOCOLS.*/a\\tdhcperfcli \\' <FreeRADIUS sources>/Makefile`__<br>

Then configure and build FreeRADIUS as described previously.

### Update PATH

You will need to update your PATH environment variable so you can execute the program from wherever.<br>
For example:
>__`export PATH=/opt/freeradius/4.0.x/sbin:$PATH`__

Finally, check installation:

>__`dhcperfcli -v`__

All set!
