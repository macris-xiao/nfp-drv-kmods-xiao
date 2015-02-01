NFP Kernel Drivers
------------------

Building and installing
-----------------------

Building and installing for the currently running kernel:
$ make
$ sudo make install


To clean up use the 'clean' target
$ make clean

For a more verbose build use the 'noisy' target
$ make noisy

To override the kernel version to build for set 'KVER':
$ make KVER=<version> 
$ sudo make KVER=<version> install

The Makefile searches a number of standard location for the configured
kernel sources. To override the location set 'KSRC'
$ make KSRC=<location of kernel source> 


Additional targets:
- coccicheck: Runs Coccinelle/coccicheck
  requires coccinelle to be installed, e.g., sudo apt-get install coccinelle
- sparse: Runs sparse, a tool for static code analysis 
  requires the sparse tool to be installed, e.g., sudo apt-get install sparse


nfp.ko parameters
-----------------

nfp_mon_err=false           ECC Monitor (default = disbled) (bool)
nfp_dev_cpp=true            NFP CPP /dev interface (default = enabled) (bool)
nfp_net_null=false          Null net devices (default = disabled) (bool)
nfp_net_vnic=true           vNIC net devices (default = enabled) (bool)
nfp_net_vnic_pollinterval=10 Polling interval for Rx/Tx queues (in ms) (uint)
nfp_net_vnic_debug=0        Enable debug printk messages (uint)
nfp_mon_err_pollinterval=10 Polling interval for error checking (in ms) (uint)
hwinfo_wait=10              -1 for no timeout, or N seconds to wait for board.state match (int)
hwinfo_debug                Enable to log hwinfo contents on load (int)
board_state=15              board.state to wait for (int)
nfp6000_explicit_bars=4     Number of explicit BARs (0-4) (int)
nfp6000_debug=0             Enable debugging for the NFP6000 PCIe (int)
nfp3200_debug=0             Enable debugging for the NFP3200 PCIe (int)
