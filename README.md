# usermode_compat
**Usermode Compatibility for Linux Kernel Code (UMC)**  
A shim for running some Linux kernel code in usermode  
*David A. Butterfield*

The initial implementation of UMC emulates a sufficient subset of Linux kernel
internal functions to support an SCST-based iSCSI storage server (based on
~80,000 lines of SCST kernel sources) running entirely in usermode on an
unmodified kernel.

UMC emulates the necessary functionality using calls to the sys_service API
implemented by the Multithreaded Event Engine (MTE) in libmte, and to functions
in libpthread, libaio, libdl, and libc.

Most of the UMC code resides in usermode_lib.h <SMALL>(~2500 lines of code)</SMALL>,
supported by another ~300 LOC in usermode_lib.c.  Another ~700 LOC implements a
translation between the kernel's proc_dir_entry calls and fuse(8) calls, to
support the kernel module's interface to system applications.

Although there are presently a small number of places in the code using
Linux-specific system call options, these could easily be abstracted out to
allow the possibility of running SCST also on _non_-Linux systems having gcc and
the necessary libraries.

**UMC depends on**
<A HREF="https://github.com/DavidButterfield/MTE#user-content-mte">Multithreaded Engine (libmte)</A>
    &mdash; a high-performance multi-threaded usermode event dispatching engine.

#### UMC Client
<A HREF="https://github.com/DavidButterfield/SCST-Usermode-Adaptation#user-content-scst-usermode-adaptation">
         iSCSI-SCST Storage Server Usermode Adaptation</A>
    &mdash; a port of the SCST iSCSI storage server to run entirely in usermode on an unmodified Linux kernel.
    &nbsp;
<A HREF="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_Usermode.html">
         <I>[Paper describing the project in detail]</I></A>

#### Diagrams showing the relationship between UMC, MTE, and SCST
* * *
![SCST usermode service map](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_usermode_service_map.png
                             "SCST Usermode Service Map")
* * *
![SCST usermode header and library inclusions](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_usermode_includes.png
                                               "SCST Usermode Header and Library Inclusions")
* * *
