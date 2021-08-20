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

The following setup is required on the `DUT`.

### Centos 8:

#### Centos package dependencies

```
dnf install dwarves clang python27
```
Set `python27` as system-wide python command:
```
ln -sf /usr/bin/python2.7 /usr/bin/python
```

#### Install a newer Linux kernel

For example, either
[linux-stable-private](https://github.com/Corigine/linux-stable-private "https://github.com/Corigine/nti-private")
or
[net-next-private](https://github.com/Corigine/net-next-private "https://github.com/Corigine/nti-private")

#### Build bpftool

For example, if using net-next-private:
```
cd net-next-private
make -C tools/lib/bpf
make -C tools/lib/bpf install
make -C tools/bpf/bpftool install
export LIBBPF_PATH=/root/net-next-private/tools/lib/bpf/
```

#### Install nfp-sdk

For example:

```
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-sdk/releases/6.3.0/6.3.0.6/nfp-toolchain-6.3.0.6-0-5001.x86_64.rpm
dnf -y install nfp-toolchain-6.3.0.6-0-5001.x86_64.rpm
```

#### Add SDK directory to path:
```
NETRONOME_DIR=${NETRONOME_DIR:-"/opt/netronome"}
PATH=${PATH}:${NETRONOME_DIR}/bin
```

#### Install nfp-drv-kmods-private

```
git clone https://github.com/Corigine/nfp-drv-kmods-private.git
cd nfp-drv-kmods-private/
make
make install
make test_prepare
```

#### Install NTI Python requirements:

```
enum34
python-dateutil
paramiko
pyelftools
scapy
Flask
Flask-SQLAlchemy
Flask-WTF
```

#### Clone NTI

```
git clone https://github.com/Corigine/nti-private.git
```

#### Configure passwordless login (optional)

```
ssh-keygen -t rsa -N ''
ssh-copy-id root@localhost
```

Most importantly, make sure that the tests files are built correctly using:
`make test_prepare`. Also make sure to update the `$PATH` variable to include
the NFP SDK binaries: `PATH=${PATH}:${NETRONOME_DIR}/bin`


## Setting up the test config files:

In order to run the tests using the nti tool, a config file must be created that
specifies the details of the DUT, EP and other test parameters. Information
regarding the parameters used in the config files can be found in
[nfp-drv-kmods-private/tests/drv_grp.py](https://github.com/Corigine/nfp-drv-kmods-private/blob/main/tests/drv_grp.py "https://github.com/Corigine/nfp-drv-kmods-private/blob/main/tests/drv_grp.py").

An example config:
```
[root@test1 testing]# cat dut.cfg
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
netdevfw: /lib/firmware/netronome/nic_AMDA0099-0001_2x25.nffw
nfpkmods: /root/testing/nfp-drv-kmods-private/src
samples=/root/testing/nfp-drv-kmods-private/tests/samples
serial= 00:15:4d:12:20:d4

[HostA]
name: test2.zay.corigine.com
ethA: ens4np0
addrA: 10.7.1.2/24
addr6A: fc00:7:1:1::2/64
reload: False
```

Something to note, if using the parameter `rm_fw_dir: True`, it might be
required to re-create the symlink in `/lib/firmware/netronome/` between tests.

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
