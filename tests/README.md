# Running the nti-based driver tests

The tests located in the nfp-drv-kmods-private/tests/ directory are run using
the
[nti](https://github.com/Corigine/nti-private "https://github.com/Corigine/nti-private")
test framework. This documentation provides information on getting a working
test environment up and running, as well as running tests.

## Setting up the test environment

The test configuration looks like this:
```
         +---------+
         |   DUT   |
         |         |
         |ethX ethY|
         +-^-----^-+
+------+   |     |   +-------+
|Host A|   |     |   |Host B*|
|  ethA<---+     +--->ethB   |
+------+             +-------+
                     *optional
```

The setup process detailed below is for machines running Centos Stream 8.
### DUT:

#### Package dependencies

```bash
dnf -y install dwarves clang python27 iproute pciutils binutils-devel openssl-devel netperf hping3 lm-sensors
```
Set `python27` as system-wide python command:
```bash
alias python=python2.7
alias pip=pip2.7
```

#### Install a newer Linux kernel

For example, either
[linux-stable-private](https://github.com/Corigine/linux-stable-private)
or
[net-next-private](https://github.com/Corigine/net-next-private)

Note that when executing certain tests the following needs to be set in the
configuration file when building the kernel:
```
CONFIG_PCI_STUB: m
CONFIG_DEBUG_INFO_BTF: y
```
#### Build bpftool

For example:
```bash
cd /root/linux-kernel-source
make -C tools/lib/bpf
make -C tools/lib/bpf install
make -C tools/bpf/bpftool install
export LIBBPF_PATH=/root/linux-kernel-source/tools/lib/bpf/
```

#### Install nfp-sdk

For example:

```bash
cd /root/
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-sdk/releases/6.4.0/6.4.0.9/nfp-toolchain-6.4.0.9-0-5072.x86_64.rpm
dnf -y install nfp-toolchain-6.4.0.9-0-5072.x86_64.rpm
```

#### Add SDK directory to path:
```
NETRONOME_DIR=${NETRONOME_DIR:-"/opt/netronome"}
PATH=${PATH}:${NETRONOME_DIR}/bin
```

#### Install nfp-bsp

Most of the tests require not only the nfp-sdk but also the nfp-bsp.
An example of how to install this can be seen below:
```bash
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-bsp/distros/default/x86_64/rpm/nfp-bsp_2021.08.09.1610_1_x86_64.rpm
dnf -y install nfp-bsp_2021.08.09.1610_1_x86_64.rpm
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-bsp/distros/default/x86_64/rpm/nfp-bsp-dev_2021.08.09.1610_1_x86_64.rpm
dnf -y install nfp-bsp-dev_2021.08.09.1610_1_x86_64.rpm
```

After installing the nfp-bsp packages on the machine it is a good idea to then
update the bsp version on the NIC itself using the following command:
```bash
nfp-fw-update -Z 0000:02:00.0 --update
```
with the PCI address of the NIC you intend to use for the tests.
#### Install nfp-drv-kmods-private

```bash
git clone https://github.com/Corigine/nfp-drv-kmods-private.git
cd nfp-drv-kmods-private/
make
make install
make test_prepare
```
Note that when testing on nfp 3800 it is necessary to run
```make test_prepare CHIP=nfp-38xx``` instead of simply ```make test_prepare```
in order to compile the firmwares under the `tests/samples/mefw` directory.

### EP

The EP can be provisioned in exactly the same way as the DUT with one
difference in the installation of the driver, and additional step,
the installation of firmware for the smartNIC.

#### Driver
The process for installing the driver for the EP differs only in that
you do not have to build with the `test_prepare` tag. The installation
of the driver on the EP is accomplished as follows:
```bash
git clone https://github.com/Corigine/nfp-drv-kmods-private.git
cd nfp-drv-kmods-private/
make
make install
```

#### Firmware
The EP does not require specific firmware per test, as in the case of the DUT,
and as such can simply use the basic coreNIC firmware.

The following commands detail the installation of the coreNIC firmware and
reloading of the driver:
```bash
wget http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/rpm/agilio-nic-firmware-2.1.16.1-1.noarch.rpm
dnf -y install agilio-nic-firmware-2.1.16.1-1.noarch.rpm
cd /root/nfp-drv-kmods-private/
rmmod nfp && insmod src/nfp.ko
```

### Test Orchestrator
The test orchestrator is simply there to execute the tests and does not
require a smartNIC of it's own, it can even be a VM.

Follow the same steps as for the DUT to install `python2.7`, but the
other software dependencies are not necessary for the orchestrator as no
building is being done on this machine.

#### Obtain driver and test files
The test interface reinstalls the driver and firmware on the DUT for each test,
however, the driver that is installed needs to be built on the same kernel
version that the DUT is running, which is why we built the driver on the DUT in
the first place.

The test infrastructure also needs to be able to ssh into both the EP and DUT
so it makes sense to configure passwordless login to these devices, the process
is quite simple and is detailed below:
```bash
ssh-keygen -t rsa -N ''
ssh-copy-id root@DUT-domain-name
ssh-copy-id root@EP-domain-name

```

Once passwordless login is setup it is easiest to simply copy the entire driver
folder from the DUT to the orchestrator using the following command:
```
scp -r root@DUT-domain-name:/root/nfp-drv-kmods-private /root/
```

#### Install NTI Python requirements:

```
pip install enum34 python-dateutil paramiko pyelftools scapy Flask Flask-SQLAlchemy Flask-WTF
```

#### Clone NTI

```
git clone https://github.com/Corigine/nti-private.git
```

## Setting up the test config files:

In order to run the tests using the nti tool, a config file must be created that
specifies the details of the DUT, EP and other test parameters. Information
regarding the parameters used in the config files can be found in
[nfp-drv-kmods-private/tests/drv_grp.py](https://github.com/Corigine/nfp-drv-kmods-private/blob/main/tests/drv_grp.py "https://github.com/Corigine/nfp-drv-kmods-private/blob/main/tests/drv_grp.py").

An example config:
```
[General]
noclean: True
force_fw_reload: True
rm_fw_dir: True
installed_drv: False
tun_net: 10.10.1

[DUT]
name: test1.zay.corigine.com
ethX: ens4np0
addrX: 10.7.1.1/24
addr6X: fc00:7:1:1::1/64
netdevfw: /root/firmware/corenic/nic_AMDA0099-0001_2x25.nffw
netdevfw_nfd3: True
nfpkmods: /root/nfp-drv-kmods-private/src
samples=/root/nfp-drv-kmods-private/tests/samples
serial= 00:15:4d:12:20:d4

[HostA]
name: test2.zay.corigine.com
ethA: ens4np0
addrA: 10.7.1.2/24
addr6A: fc00:7:1:1::2/64
reload: False
```
`serial` refers to the serial number of the smartNIC itself and can be obtained
by executing the following command on the DUT:
```bash
lspci -d "19ee:" -v  | sed -n "s/-/:/g;s/.*Serial Number \(.*\)/\\1/p" | cut -d ':' -f 1-6
```
`netdevfw` refers to the specific firmware loaded onto the DUT and is test
specific, see [the relevant section](#test-specific-firmware). This is
where the firmware files themselves are located on the orchestrator.

`netdevfw_nfd3` specifies whether the DUT netdev firmware is NFD3-based. This
flag is only necessary when making use of a Kestrel-based NFP.

Notes:
- if using the parameter `rm_fw_dir: True`, it might be
required to re-create the symlink in `/lib/firmware/netronome/` between tests.
- Only use absolute paths in the config file, i.e. no "~/"

## Running the tests in the nfp-drv-kmods-private/tests/ folder:

The tests are run from the context of the driver source directory:
`cd nfp-drv-kmods-private/`

To run a specific test, the following command can be used:

```
../nti-private/ti/ticmd -c ../<config>.cfg run tests.<test_group>.<test_to_run>
```

To find further details regarding the `ticmd` tool, the help command can be
used:
```
../nti-private/ti/ticmd -h
```
For details regarding the possible tests to run, the `../nti-private/ti/ticmd
list tests` command is used, which will return:
```
Test Groups for project tests:
tests.rand : Randomized tests of NFP Linux driver.
tests.ebpf_perf : BPF tests to detect performance regressions.
tests.reboot : Unit tests used for NFP Linux driver, requiring DUT reboot.
tests.ebpfdrv : BPF tests used for NFP Linux driver.
tests.rand_err : Randomized tests of NFP Linux driver.
tests.unit : Unit tests used for NFP Linux driver.
tests.flower : Basic flower tests of NFP Linux driver.
tests.ebpf : BPF tests used for NFP Linux driver.
tests.netdev : FW-independent NIC tests used for NFP Linux driver.
tests.setup : Check environment for running the NFP Linux driver tests.
tests.abm : ABM NIC tests used for NFP Linux driver.
tests.ktls : kTLS NIC tests used for NFP Linux driver.
tests.ebpf_perf_drv : BPF tests to detect performance regressions.
tests.reload : Unit tests used for NFP Linux driver
```
To display additional debug information, verbose mode (`-v`) can be used , for
example:

```
../nti-private/ti/ticmd -v \
                        -c ../<config>.cfg run tests.<test_group>.<test_to_run>
```

### Test Specific Firmware
This section contains a table detailing the appropriate firmware to use for
each test group.

| Test group    | Test name        | Firmware to use               | Where to find the firmware
| ------------- | ---------------- | ----------------------------- | --------------------------
| abm           |                  | abm                           | 
| ktls          |                  | tls                           |
| ebpf          |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| ebpfdrv       |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| ebpf_perf     |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| ebpf_perf_drv |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| rand          |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| rand_err      |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| flower        |                  | flower                        | http://storage-01.cpt.corigine.com/cloud/binaries/disa/releases/tar
| unit          | sriov_ndos       | SRIOV                         | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| unit          | fec_modes        | SRIOV                         | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| unit          | ifstats_reconfig | SRIOV                         | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| unit          |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| netdev        | repr_caps        | flower                        | http://storage-01.cpt.corigine.com/cloud/binaries/disa/releases/tar
| netdev        | coalesce_pf      | SRIOV                         | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| netdev        | coalesce_vf      | SRIOV                         | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| netdev        |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| reboot        |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| reload        |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz
| setup         |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/2.1/tgz

### Check test setup
Finally, you can check if your test setup is properly provisioned by running
the `test.setup` test group. From within the `nfp-drv-kmods-private`
directory on the test orchestrator run the following command:
```
../nti-private/ti/ticmd -v -c ../<config>.cfg run tests.setup
```
