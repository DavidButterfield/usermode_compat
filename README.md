# usermode_compat
**Usermode Compatibility for Linux Kernel Code (UMC)**  
A shim for running some Linux kernel code in usermode  
*David A. Butterfield*

<SMALL>

The initial implementation of UMC emulates a sufficient subset of Linux kernel
internal functions to support an SCST-based iSCSI storage server (based on
~80,000 lines of SCST kernel sources) running entirely in usermode on an
unmodified kernel.

UMC emulates the necessary functionality using calls to the sys_service API
implemented by the Multithreaded Event Engine (MTE) in libmte, and to functions
in libpthread, libaio, libdl, and libc.

Most of the UMC code resides in usermode_lib.h (~2500 lines of code); supported
by another ~300 LOC in usermode_lib.c.  Another ~700 LOC implements a
translation between the kernel's proc_dir_entry calls and fuse(8) calls, to
support the kernel module's interface to system applications.

Although there are presently a small number of places in the code using
Linux-specific system call options, these could easily be abstracted out to
allow the possibility of running SCST also on _non_-Linux systems having gcc and
the necessary libraries.

**UMC Depends on**
<A HREF="https://github.com/DavidButterfield/MTE">Multithreaded Engine (libmte)</A>
    &mdash; a high-performance multi-threaded event dispatching engine for usermode.

**UMC Client**
  
<A HREF="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/">
         <STRONG>iSCSI-SCST Storage Server Usermode Adaptation</STRONG></A>
    &mdash; a port of the SCST iSCSI storage server to run entirely in usermode on an unmodified Linux kernel. &nbsp;
<A  HREF="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_Usermode.html">
	 <I>[Paper describing the project in detail]</I></A>

**Diagrams showing the relationship between UMC, MTE, and SCST**  

<A  HREF="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_usermode_service_map.pdf">
<IMG SRC="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_usermode_service_map.png"
 BORDER=1 style="padding:5px; border-color: grey" WIDTH=720></A>

<P>
<A  HREF="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_usermode_includes.pdf">
<IMG SRC="https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_usermode_includes.png"
 BORDER=1 style="padding:5px; border-color: grey" WIDTH=720></A>

</SMALL>
