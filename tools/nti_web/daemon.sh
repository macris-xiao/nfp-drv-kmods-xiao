#!/bin/bash -x

### Load the setup-specific configuration

[ ! -f config.sh ] && echo "No $PWD/config.sh found" && exit 1
. config.sh

# config.sh is expected to export:
#   DUT: IP or DNS name of remote machine

###

NPROC=$(grep -c processor /proc/cpuinfo)

###

bold() {
    echo -e "\e[1m" $@ "\e[0m"
}

wait_for_dut()
{
    bold "Waiting for DUT ($DUT) at $(date)"

    while ! ping -c1 $DUT || ! ssh root@$DUT true ; do
	sleep 5
    done

    echo Done at $(date)
}

update_nti() {
    (
	if [ -e nti/ ]; then
	    cd nti/
	    git pull
	else
	    git clone ssh://bbslave@source.netronome.com/data/git/repos/nti.git
	fi
    )
}

dut_update_kernel()
{
    bold "Updating the kernel"

    (
	if [ -e net-next/ ]; then
	    cd net-next/
	    git pull --depth=1
	else
	    git clone --depth=1 git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git
	    cd net-next/
	fi

	# Get running version
	DUT_kernel=$(ssh root@$DUT uname -r)
	# Get git version (one we will install)
	V=$(make --quiet kernelrelease)

	if [ $DUT_kernel == $V ]; then
	    return
	fi

	# Copy the current config
	scp root@$DUT:/boot/config-$DUT_kernel .config
	# Make sure we append git version
	echo 'CONFIG_LOCALVERSION_AUTO=y' >> .config
	echo 'CONFIG_NFP_DEBUG=y' >> .config
	# Update .config to new code
	make olddefconfig

	# Build
	make -j $NPROC

	# Remove old kernels with LOCALVERSION
	ssh root@$DUT "rm $(ls /boot/ | grep '.-g[a-f0-9]*$')"

	# Install modules locally into /tmp and copy them over
	MOD_DIR=$(mktemp -d)

	make INSTALL_MOD_PATH=$MOD_DIR modules_install
	rm -f $MOD_DIR/lib/modules/*/{source,build}
	rsync -avhHAX $MOD_DIR/lib/modules/* root@$DUT:/lib/modules/
	rm -rf $MOD_DIR

	# Copy over kernel, System.map and config
	scp arch/x86/boot/bzImage root@$DUT:/boot/vmlinuz-$V
	scp System.map root@$DUT:/boot/System.map-$V
	scp .config root@$DUT:/boot/config-$V

	# Build initramfs and create new GRUB config
	ssh root@$DUT mkinitramfs -o /boot/initrd.img-$V $V
	ssh root@$DUT grub-mkconfig -o /boot/grub/grub.cfg

	ssh root@$DUT reboot

	# Build libraries etc.
	make -C tools/lib/bpf/
    )
}

update_driver() {
    git pull
    make KSRC=net-next/ -j $NPROC
    export LIBBPF_PATH=$(pwd)/net-next/tools/lib/bpf/
    make KSRC=net-next/ -j $NPROC test_prepare
}

###

last_kernel_update=x

while true; do
    # Update all repos only once a day
    if [ $last_kernel_update != $(date '+%x') ]; then
	wait_for_dut

	update_nti
	dut_update_kernel
	update_driver

	wait_for_dut

	last_kernel_update=$(date '+%x')
    fi

    # Run all NTI tests
    ./tools/nti_web/nti_run_all.sh

    # Parse all results into a website
    ./tools/nti_web/tests_displayer.py auto_logs/

    sleep 5
    echo Loop done
done
