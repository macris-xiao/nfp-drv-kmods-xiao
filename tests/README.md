# Running the nti-based driver tests

The tests located in the nfp-drv-kmods-private/tests/ directory are run using
the
[nti](https://github.com/Corigine/nti-private "https://github.com/Corigine/nti-private")
test framework. This documentation provides information on getting a working
test environment up and running, as well as running tests.

## Setting up the test environment

The topology of the testing cluster is as seen below:
```
         +---------+
         |   DUT   |
         |         |
         |ethX ethY|
         +-^-----^-+
+------+   |     |   +-------+
|Host A|   |     |   |Host B|
|  ethA<---+     +--->ethB   |
+------+             +-------+
```

### DUT:

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
One can either install a kernel from source by cloning one of the above
mentioned repos and configuring them appropriately, or by installing one of the
pre-configured kernel packages available on the Azure cloud storage at
```
internal/tmp/linux-stable-builds/
```

The packages come in the form of a tarball, for example:
<b>kernel-5.19.9-drv-616.tar.gz</b>
Extracting this will show the following files:
##### CentOS Stream 8
```
kernel-5.19.9_drv_616-1.x86_64.rpm
kernel-devel-5.19.9_drv_616-1.x86_64.rpm
kernel-headers-5.19.9_drv_616-1.x86_64.rpm
```
##### Ubuntu 20.04
```
linux-headers-5.19.9-drv-616_5.19.9-drv-616-1_amd64.deb
linux-image-5.19.9-drv-616-dbg_5.19.9-drv-616-1_amd64.deb
linux-image-5.19.9-drv-616_5.19.9-drv-616-1_amd64.deb
linux-libc-dev_5.19.9-drv-616-1_amd64.deb
linux-upstream_5.19.9-drv-616-1.diff.gz
linux-upstream_5.19.9-drv-616-1.dsc
linux-upstream_5.19.9-drv-616-1_amd64.buildinfo
linux-upstream_5.19.9-drv-616-1_amd64.changes
linux-upstream_5.19.9-drv-616.orig.tar.gz
```

For <b>CentOS Stream 8</b>, one must simply install all of the extracted
<b>.rpm</b> package files using the <b>dnf</b> command line utility.

For <b>Ubuntu 20.04</b>, one must first install all of the extracted <b>.deb</b>
package files using either the <b>dpkg</b> or <b>apt</b> command line utilities.
However, this does not include the Kconfig files in the kernel source directory,
which are necessary in order to build bpftool in the step to follow. To ensure
the presence of these files one must extract the contents of
<b>linux-upstream_5.19.9-drv-616.orig.tar.gz</b> into the kernel source
directory using the following command:

```bash
sudo tar xvfz linux-upstream_5.19.9-drv-616.orig.tar.gz --strip-components 1 -C /usr/src/linux-headers-5.19.9-drv-616/
```

Once the new kernel is installed on the DUT, restart the machine.

#### Package dependencies

##### CentOS Stream 8
```bash
dnf -y install dwarves clang python27 iproute pciutils binutils-devel openssl-devel netperf hping3 lm_sensors
```
##### Ubuntu 20.04
```bash
apt -y install dwarves clang python2.7 iproute2 pciutils binutils-dev libssl-dev netperf hping3 lm-sensors
```

Set `Python 2.7` as system-wide python command:
##### CentOS Stream 8
```bash
sudo update-alternatives --install /usr/bin/unversioned-python python /usr/bin/python3 0
sudo update-alternatives --install /usr/bin/unversioned-python python /usr/bin/python2 51
```
##### Ubuntu 20.04
```bash
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 0
sudo update-alternatives --install /usr/bin/python python /usr/bin/python2.7 51
```




#### Build bpftool
bpftool must be built and installed using the newly installed kernel. For this,
one must first determine the kernel source directory.

If the kernel was installed from source by cloning one of the above-mentioned
repos and configuring it oneself before building and installing, this source
directory will simply be the location of the cloned repo.

If the kernel was installed using packages, then the kernel source directory,
hereafter defined as <b>$KSRC</b>, will be located in
##### CentOS Stream 8
```bash
/usr/src/kernels/5.19.9-drv-616
```
##### Ubuntu 20.04
```bash
/usr/src/linux-headers-5.19.9-drv-616/
```

For example:
```bash
cd $KSRC
make -C tools/lib/bpf
make -C tools/lib/bpf install
make -C tools/bpf/bpftool install
export LIBBPF_PATH=/root/linux-kernel-source/tools/lib/bpf/
```

#### Install nfp-sdk

For example:

##### CentOS Stream 8
```bash
cd /root/
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-sdk/releases/6.4.0/6.4.0.9/nfp-toolchain-6.4.0.9-0-5072.x86_64.rpm
dnf -y install nfp-toolchain-6.4.0.9-0-5072.x86_64.rpm
```

##### Ubuntu 20.04
```bash
cd /root/
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-sdk/releases/6.4.0/6.4.0.9/nfp-toolchain_6.4.0.9-5072-2_amd64.deb
apt -y install ./nfp-toolchain_6.4.0.9-5072-2_amd64.deb
```

#### Add SDK directory to path:
```
NETRONOME_DIR=${NETRONOME_DIR:-"/opt/netronome"}
PATH=${PATH}:${NETRONOME_DIR}/bin
```

#### Install nfp-bsp

Most of the tests require not only the nfp-sdk but also the nfp-bsp.
An example of how to install this can be seen below:
##### CentOS Stream 8
```bash
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-bsp/releases/rpm/nfp-bsp_22.09-0.el8.x86_64.rpm
dnf -y install nfp-bsp_22.09-0.el8.x86_64.rpm
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-bsp/releases/rpm/nfp-bsp-dev_22.09-0.el8.x86_64.rpm
dnf -y install nfp-bsp-dev_22.09-0.el8.x86_64.rpm
```

##### Ubuntu 20.04
```bash
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-bsp/releases/deb/nfp-bsp_22.09-0.bionic_amd64.deb
apt -y install ./nfp-bsp_22.09-0.bionic_amd64.deb
wget http://storage-01.cpt.corigine.com/cloud/binaries/nfp-bsp/releases/deb/nfp-bsp-dev_22.09-0.bionic_amd64.deb
apt -y install ./nfp-bsp-dev_22.09-0.bionic_amd64.deb
```

After installing the nfp-bsp packages on the machine it is a good idea to then
update the bsp version on the NIC itself using the following command:
```bash
nfp-fw-update -Z 0000:02:00.0 --update
```
with the PCI address of the NIC you intend to use for the tests.

#### Install llvm and clang
It is recommended to install the pre-built <b>llvm</b> and <b>clang</b>
packages, to ensure the correct version and dependencies are installed,
regardless of OS.

Similarly to the custom kernel packages, these packages can be found on the
Azure storage server at

```
/mnt/cloud/binaries/misc/llvm/
```

After downloading a tarball, they can be installed using the following commands:

##### CentOS Stream 8
```bash
sudo tar xvfz llvm-toolchain-13-2022-06-20.tar.gz
sudo dnf -y --nogpgcheck install ./centos8/*.rpm
```
##### Ubuntu 20.04
```bash
sudo tar xvfz llvm-toolchain-13-2022-06-20.tar.gz
sudo dpkg -i ubuntu2004/*.deb
```

#### Install nfp-drv-kmods-private

```bash
git clone https://github.com/Corigine/nfp-drv-kmods-private.git
cd nfp-drv-kmods-private/
make
make test_prepare
```

Depending on the user, one may wish to also install the driver on the DUT
using the ```make install``` Makefile target, if one is working on the tests
themselves this can be helpful to save the nti framework and Orchestrator
from having to install it each time an instance of the tests is run.

But generally speaking it is preferred to have the installation handled by the
Orchestrator as it will then also uninstall the driver being tested, resulting
in a cleaner setup once testing is finished.

*Note that when testing on nfp 3800 it is necessary to run
```make test_prepare CHIP=nfp-38xxc``` instead of simply ```make test_prepare```
in order to compile the firmwares under the `tests/samples/mefw` directory.

### EP

The EP can be provisioned in exactly the same way as the DUT with one
difference in the installation of the driver, and additional step,
the installation of firmware for the smartNIC.

#### Driver
The process for installing the driver for the EP differs slightly, as this is
not the version of the driver being tested, it is only really important that the
versions are not so different that the tests fail due to missing features on the
EP driver.

If the versions are close enough then the EP can simply use the in-tree driver,
enabled with the ```modprobe nfp``` command.

If the versions are too out of date, then it is best to install the out of tree
driver, the process is similar to that on the DUT, with substitution of the
```install``` target for the previously used ```test_prepare``` target.
The installation of the driver on the EP is accomplished as follows:
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
## Provisioning using Ansible

While the above process is acceptable to get the test framework up and running,
certain tests require additional dependencies which are not detailed here, such
as the installation of OVS required by the <b>tests.flower</b> test group.

As new tests are developed, the Ansible provisioning playbook will be updated
more regularly than this document. For these reasons it is recommended to
instead provision the testing cluster using the ```provision_ci_dev_drv.yaml```
playbook in the [ci-libs](https://github.com/Corigine/ci-libs "https://github.com/Corigine/ci-libs")
repository.

This section will detail the use of Ansible to provision a cluster of machines
for Driver regression tests. The following example cluster in the za-cpt lab
will be used:

| Hostname                    | Role         |
|-----------------------------|--------------|
| example_vm.cpt.corigine.com | Orchestrator |
| rick.cpt.corigine.com       | DUT          |
| morty.cpt.corigine.com      | EP           |

Working on the Orchestrator VM, clone the ```ci-libs``` repo:
```bash
git clone https://github.com/Corigine/ci-libs.git
```

Install ansible on the Orchestrator VM:
##### CentOS Stream 8
```bash
sudo dnf -y epel-release python3 python3-pip sshpass
pip3 install jmespath ansible
```
##### Ubuntu 20.04
```bash
sudo apt -y epel-release python3 python3-pip sshpass
pip3 install jmespath ansible
```

This cluster then needs to be added to the inventory file for the za-cpt lab,
located in ```ansible/inventories/za-cpt/hosts.yaml``` in the form:

```yaml
driver_regressions:
  hosts:
    example_vm.cpt.corigine.com:       # Orchestrator
    rick.cpt.corigine.com:             # DUT
    morty.cpt.corigine.com:            # EP
  children:
    driver_regressions_orch:
      hosts:
        example_vm.cpt.corigine.com:       # Orchestrator
    driver_regressions_dut:
      hosts:
        rick.cpt.corigine.com:             # DUT
    driver_regressions_ep:
      hosts:
        morty.cpt.corigine.com:            # EP
```
Once the inventory file has been updated, the custom kernel and llvm tarballs
need to be copied to the appropriate directories using the following command:

```bash
mkdir ci-libs/ansible/roles/kernel_installer/files
cp kernel-5.19.9-drv-616.tar.gz ci-libs/ansible/roles/kernel_installer/files/

mkdir ci-libs/ansible/roles/llvm/files
cp llvm-toolchain-13-2022-06-20.tar.gz ci-libs/ansible/roles/llvm/files/
```
Finally, run the ```provision_ci_dev_drv.yaml``` playbook:

```bash
cd ci-libs/ansible
ansible-playbook provision_ci_dev_drv.yaml -i inventories/za-cpt/hosts.yaml -e \
'{"target":"driver_regressions","kernel_src":"custom_package","kernel_file_tar":"kernel-5.19.9-drv-616.tar.gz","ci_dev_drv_install":"false","drv_llvm_install_src":"custom_package","dut_drv_version":"<DRIVER_VERSION_TO_TEST>"}' \
-t "provision" --ask-vault-password
```

After the playbook is run, all that remains is to copy the built driver across
to the Orchestrator from the DUT, as detailed in the previous section, and set
up the test config files.
## Setting up the test config files:

In order to run the tests using the nti tool, a config file must be created that
specifies the details of the DUT, EP and other test parameters. Information
regarding the parameters used in the config files can be found in
[nfp-drv-kmods-private/tests/drv_grp.py](https://github.com/Corigine/nfp-drv-kmods-private/blob/main/tests/drv_grp.py "https://github.com/Corigine/nfp-drv-kmods-private/blob/main/tests/drv_grp.py").

An example config:
```
[General]
noclean: False
force_fw_reload: True
rm_fw_dir: True
installed_drv: False
tun_net: 10.10.1

[DUT]
name: rick.cpt.corigine.com
ethX: ens4np0 ens4np1
addrX: 169.254.1.1/24 169.254.2.1/24
addr6X: fc00:7:1:1::1/64 fc00:7:1:2::1/64
netdevfw: ../firmware/nic_AMDA0099-0001_2x25.nffw
netdevfw_dir: ../firmware/
netdevfw_nfd3: True
nfpkmods: ../nfp-drv-kmods-private/src
samples: ../nfp-drv-kmods-private/tests/samples
serial:  00:15:4d:16:57:fb

[HostA]
name: morty.cpt.corigine.com
ethA: ens5np0 ens5np1
addrA: 169.254.1.2/24 169.254.2.2/24
addr6A: fc00:7:1:1::2/64 fc00:7:1:2::2/64
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
- Newer Corigine cards will have a vendor ID of `1da8`, not `19ee`. Adjust the `lspci`
command accordingly if using a newer card.
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
each test group. Test groups requiring multiple types of firmware for different
tests within the same group now have that firmware type prepended to the test
name.

| Test group    | Test name        | Firmware to use               | Where to find the firmware
| ------------- | ---------------- | ----------------------------- | --------------------------
| abm           |                  | abm                           | 
| ktls          |                  | tls                           |
| ebpf          |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| ebpfdrv       |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| ebpf_perf     |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| ebpf_perf_drv |                  | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/bpf/tgz
| rand          |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| rand_err      |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| flower        |                  | flower                        | http://storage-01.cpt.corigine.com/cloud/binaries/disa/releases/tgz
| unit          | multi.*          | SRIOV *or* CoreNIC            | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| netdev        | multi.*          | SRIOV *or* CoreNIC            | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| netdev        | sriov.*          | SRIOV                         | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| netdev        | flower.*         | flower                        | http://storage-01.cpt.corigine.com/cloud/binaries/disa/releases/tgz
| netdev        | bpf.*            | bpf *or* bpf_upd *or* bpf_big | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| reboot        |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| reload        |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz
| setup         |                  | coreNIC                       | http://storage-01.cpt.corigine.com/cloud/binaries/nic/releases/tgz

### Check test setup
Finally, you can check if your test setup is properly provisioned by running
the `test.setup` test group. From within the `nfp-drv-kmods-private`
directory on the test orchestrator run the following command:
```
../nti-private/ti/ticmd -v -c ../<config>.cfg run tests.setup
```
