.. Copyright (c) 2018 Netronome Systems, Inc.
.. _tests:

==========================
Running Linux driver tests
==========================

Introduction
============

Driver tests are using NTI. They do however require special firmware and driver
shim module to be built. To use the driver tests, you need to clone the
nfp-drv-kmods repo and the nti repo. One can use any of the kernel compatible
firmware images, such as CoreNIC or Disa, for the driver tests:

- http://pahome.netronome.com/releases-intern/nic/builds/2.0/tgz/agilio-nic-firmware-2.0.10.tgz
- http://pahome.netronome.com/releases-intern/disa/firmware/disa-2.9.A-AOTC-2.9.A.16-2018-05-08_firmware.tar.gz

Note: Some of the tests.unit tests are failing with the Disa firmware and still
needs to be updated.

Repos
=====

::

    $ git clone git://source.netronome.com/nfp-drv-kmods.git
    $ git clone git://source.netronome.com/nti.git

Python
======

The tests are written in Python, some need pyelftools. New distros should have
it packaged, in case yours doesn't (Ubuntu 14.04) run
``pip install pyelftools``.

Config files
============

Here is an example configuration for Carbon::

    [General]
    noclean: False
    tun_net: 10.9.1.

    [DUT]
    name: 172.22.2.132
    ethX: p6p1 p6p2
    addrX: 10.25.1.1/24 10.25.2.1/24
    addr6X: fc00:2:2:3::1/64 fc00:3:2:3::1/64
    nfpkmods=/home/jkicinski/devel/nfp-drv-kmods/src
    netdevfw_dir=/home/jkicinski/devel/nfp-nic/firmware/nffw/
    netdevfw=/home/jkicinski/devel/nfp-nic/firmware/nffw/nic_AMDA0099-0001_2x25.nffw
    samples=/home/jkicinski/devel/nfp-drv-kmods/tests/samples
    serial=00:15:4d:12:20:7e

    [HostA]
    name: localhost
    ethA: eth8 eth10
    addrA: 10.25.1.2/24 10.25.2.2/24
    addr6A: fc00:2:2:3::2/64 fc00:3:2:3::2/64

For full description of parameters see the NTI help.

Note that driver / firmware paths may be slightly different than in CoreNIC.
The big differences are that you can select the card to run against based on
serial number and that you should list all the ports of the card (all
interfaces and addresses for them).

You may want to add::

    rm_fw_dir: True

in General section, to allow the test suite removing /lib/firmware/netronome
directory on your system (I think the CoreNIC test suite is doing that
unconditionally anyway).

Required building
=================

Once you have configs you need to build the shim driver and test firmwares out
of the nfp-drv-kmods directory::

    $ make test_prepare

If using some older nfp-drv-kmods revisions, you may need to have access to
FlowEnv and set the FLOWENV_PATH variable to where it is on your system, e.g::

    $ hg clone ssh://bbslave@source.netronome.com//data/hg/repos/flowenv.hg
    $ export FLOWENV_PATH=~/path/to/flowenv.hg/

Preferably you should also build the driver from source (you could use the
driver from CoreNIC packages but I think it is best to use the latest for test
to match the tests). Just type::

    $ make

Note: for both make commands if you are not building on the target or you
system is running different kernel than the target you have to add ``KSRC``
parameter like this::

    $ make KSRC=/lib/modules/<target kernel version from uname -r>/build

Now you should be more or less ready to run the tests :).

Note: The test framework (in particular, the XDP testcase Python file) assumes
that the tests are launched on the machine used as a SOURCE. If the tests are
launched from another machine (DUT, or a third machine), some logic regarding
directory creation are likely to fail.

Running tests
=============

There is a set of setup tests which are supposed to tell the user if their
system has the necessary commands, debian packages installed and IOMMU enabled.

Out of your nfp-drv-kmods directory execute the following::

    $ ~/nti/ti/ticmd -c cfg/hydrogen -l /tmp/logs/ run tests.setup
    tests.setup.tools                            : passed
    tests.setup.insmod                           : passed
    tests.setup.debugfs                          : passed
    tests.setup.mefw                             : passed
    tests.setup.sriov                            : passed
    tests.setup.xdp                              : FAILED
    tests.setup                                  : FAILED

The XDP test will fail for you because you probably do not have XDP things or
it is because the installed ``ip`` on DUT and test host are without ``xdp``
feature support, but do not worry we are currently not testing XDP as part of
unit tests.

As long as other setup tests are passed you can run the actual unit tests::

    $ ./ti/ticmd -c cfg/hydrogen -l /tmp/logs/ run tests.unit
    tests.unit.modinfo                           : passed
    tests.unit.serial_and_ifc                    : passed
    tests.unit.resource                          : passed
    tests.unit.nsp_eth_table                     : passed
    tests.unit.hwinfo                            : passed
    tests.unit.rtsym                             : passed
    tests.unit.fw_names                          : passed
    tests.unit.sriov                             : passed
    tests.unit.netdev                            : passed
    tests.unit.params_incompat                   : passed
    tests.unit.dev_cpp                           : passed
    tests.unit.kernel_fw_load                    : passed
    tests.unit.bsp_diag                          : passed
    tests.unit                                   : passed

The tests will reload the driver and firmware a lot.

Troubleshoot
============

If the following error occurs::

    Traceback (most recent call last):
    File "../netro-test-infra.hg/ti/ticmd", line 28, in <module>
    import netro.testinfra.main
    File "/.../netro-test-infra.hg/ti/pymod/netro/testinfra/__init__.py", line 17, in <module>
    from netro.testinfra.test import Project, Group, Test, Result
    File "/.../netro-test-infra.hg/ti/pymod/netro/testinfra/test.py", line 52, in <module>
    from netro.testinfra.nti_return_codes import NTIReturnCodes
    File "/.../netro-test-infra.hg/ti/pymod/netro/testinfra/nti_return_codes.py", line 1, in <module>
    from enum import Enum, unique
    ImportError: No module named enum

Try::

    pip install --upgrade pip enum34

You will also likely need to install ``paramiko``, ``Flask-SQLAlchemy``,
``pyelftools`` and ``scapy`` in case similar ``No module`` errors happened.

Please feel free to ping Kuba if you have any trouble with the tests.

Adding tests
============

Unit tests should be added to tests/unit/tests.py. You may want to add a new
file in the unit/ directory if your test is large. Please use NTI wrappers for
standard Linux commands wherever possible.
