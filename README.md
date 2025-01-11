# ktcpdump


ktcpdump is a network debugging tool developed using eBPF technology. 
Its key feature is that you can debug network-related functions in the Linux kernel **line by line**.



## Installation

Please download the latest binary in the [releases](https://github.com/jschwinger233/ktcpdump/releases).


## Requirements

* Linux kernel version must be larger than 5.5.
* Installed debug symbol for linux image:

    ```
    # follow https://documentation.ubuntu.com/server/reference/debugging/debug-symbol-packages/
    sudo apt-get install linux-image-`uname -r`-dbgsym
    ```


## Usage

```
ktcpdump [ -i kfunc ] [ -w file ] [ -d vmlinux-dbg ] [ -v ] expresssion
  -d, --d string    path to debug image
  -h, --help
  -i, --i strings   symbol|symbol+offset|address (default [ip_rcv,dev_hard_start_xmit])
  -v, --v           verbose output
  -w, --w string    write packets to a file (default "/tmp/a.pcap")

```


### Example commands


```
$ sudo ktcpdump -i 'tc_run+*' -d /usr/lib/debug/boot/vmlinux-`uname -r` 'dst host 1.1.1.1 and icmp'
no   skb                skb->len   pc                 ksym             addr2line
1    ffff97720b2cc900   98         ffffffff92af9281   tc_run+1         /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3927
2    ffff97720b2cc900   98         ffffffff92af92a7   tc_run+39        /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3931
3    ffff97720b2cc900   98         ffffffff92af92b8   tc_run+56        /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3930
4    ffff97720b2cc900   98         ffffffff92af92bb   tc_run+59        /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3933
5    ffff97720b2cc900   98         ffffffff92af92c4   tc_run+68        /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3936
6    ffff97720b2cc900   98         ffffffff92af92c6   tc_run+70        /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3937
7    ffff97720b2cc900   98         ffffffff92af92cd   tc_run+77        /build/linux-vCyKs5/linux-6.8.0/include/net/sch_generic.h:1060
8    ffff97720b2cc900   98         ffffffff92af92d4   tc_run+84        /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3938
9    ffff97720b2cc900   98         ffffffff92af92db   tc_run+91        /build/linux-vCyKs5/linux-6.8.0/include/linux/skbuff.h:1605
10   ffff97720b2cc900   98         ffffffff92af92e8   tc_run+104       /build/linux-vCyKs5/linux-6.8.0/include/net/sch_generic.h:1072
11   ffff97720b2cc900   98         ffffffff92af92eb   tc_run+107       /build/linux-vCyKs5/linux-6.8.0/include/net/sch_generic.h:1325
12   ffff97720b2cc900   98         ffffffff92af92f8   tc_run+120       /build/linux-vCyKs5/linux-6.8.0/include/net/sch_generic.h:863
13   ffff97720b2cc900   98         ffffffff92af9306   tc_run+134       /build/linux-vCyKs5/linux-6.8.0/arch/x86/include/asm/local.h:33
14   ffff97720b2cc900   98         ffffffff92af930d   tc_run+141       /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3941
15   ffff97720b2cc900   98         ffffffff92af9324   tc_run+164       /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3943
16   ffff97720b2cc900   98         ffffffff92af933e   tc_run+190       /build/linux-vCyKs5/linux-6.8.0/net/core/dev.c:3955
```

