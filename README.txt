NFP Kernel Drivers
------------------

Building
--------

$ make -C /lib/modules/`uname -r`/build M=`pwd` modules

Installation
------------

$ sudo make -C /lib/modules/`uname -r`/build M=`pwd` modules_install

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
