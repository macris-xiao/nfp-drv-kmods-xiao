#
# Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
#
import re
from netro.testinfra.nti_exceptions import NtiError
from ..common_test import CommonTest

class PhysPortName(CommonTest):
    def prepare(self):
        return self.kernel_min(4, 1)

    def execute(self):
        cmd =  '''
        cd /sys/class/net/

        for i in `ls`
        do
            echo $i \
                 $([ -e $i/device ] && basename $(readlink $i/device) || echo no_dev) \
                 $(cat $i/phys_port_name || echo /no_name/) \
                 $(cat $i/address || echo /no_addr/)
        done
        '''
        _, devs = self.dut.cmd(cmd)
        devices = devs.split('\n')[:-1]

        for d in devices:
            ifc, pci_dbdf, port_name, ethaddr = d.split()

            if ifc not in self.dut.nfp_netdevs:
                self.log("Skip %s, not a NFP netdev" % (ifc), '')
                continue

            if not re.match("^p\d+$", port_name) and \
               not re.match("^p\d+s\d+$", port_name) and \
               not re.match("^n\d+$", port_name) and \
               not re.match("^pf\d+$", port_name) and \
               not re.match("^pf\d+vf\d+$", port_name) and \
               not port_name == '/no_name/':
                raise NtiError('Unexpected phys_port_name: ' + port_name)

            _, pci_info = self.dut.cmd('lspci -s %s -n' % pci_dbdf)
            drvinfo = self.dut.ethtool_drvinfo(ifc)

            # Check vNIC names are not on reprs
            if not self.nfp_ifc_is_vnic(drvinfo) and \
               re.match("^n\d+$", port_name):
                raise NtiError("Non-vNIC has a vNIC phys_port_name")

            # Check repr names are not on vNICs
            if not self.nfp_ifc_is_repr(drvinfo) and \
               (re.match("^pf\d+", port_name) or
                re.match("^pf\d+vf\d+$", port_name)):
                raise NtiError("vNIC has a repr-only phys_port_name")

            # VF or flower PF vNIC without a port
            if port_name == '/no_name/' and \
               pci_info.count('19ee:6003') == 0 and \
               drvinfo["firmware-version"].count("AOTC") == 0:
                raise NtiError("Only VFs and Flower FW uses no-name vNICs")

            # VF or flower vNIC with a name
            if port_name != '/no_name/' and \
               self.nfp_ifc_is_vnic(drvinfo) and \
               (pci_info.count('19ee:6003') != 0 or \
                drvinfo["firmware-version"].count("AOTC") != 0):
                raise NtiError("VFs and Flower FW must use no-name vNICs")

            # Non-vNIC netdev on a VF
            if not self.nfp_ifc_is_vnic(drvinfo) and \
               pci_info.count('19ee:6003') != 0:
                raise NtiError("VFs with non-vNIC netdev")

            self.log("Interface %s OKAY" % (ifc), '')

        # The rest of the checks require BSP access
        if self.group.upstream_drv:
            return

        tbl = self.dut.dfs_read_raw('nth/eth_table')

        found = 0
        for d in devices:
            ifc, pci_dbdf, port_name, ethaddr = d.split()

            if pci_dbdf[5:] != self.group.pci_id:
                continue
            if not re.match("^p\d+$", port_name) and \
               not re.match("^p\d+s\d+$", port_name):
                continue

            found += 1

            labels = re.search('%s (\d*)\.(\d*)' % ethaddr, tbl)
            if not labels:
                raise NtiError('MAC addr for interface %s not found in ETH table' %
                               ifc)

            # if label X.1 exists the port is split
            is_split = tbl.find(' %s.1 ' % labels.groups()[0]) != -1
            if is_split:
                want = 'p%ss%s' % labels.groups()
            else:
                want = 'p%s' % labels.groups()[0]

            if want != port_name:
                raise NtiError('Port name incorrect want: %s have: %s' %
                               (want, port_name))

        if found != len(self.group.addr_x):
            raise NtiError('Expected %d interfaces, found %d' %
                           (len(self.group.addr_x), found))