#!/bin/bash -e

#
# DOCUMENTATION
#
# This script intends to tests patches before submission to kernel module
# project by performing multiple builds and with standard Linux patch-testing
# tools (checkpatch, sparse, coccinelle).
#
# Because using this script requires a bit of environment preparation it's best
# to keep the environment directory around and re-use it.  When you run it
# the first time it may take some time to complete, be prepared.  Also it will
# need quite a bit of disk space (~30GB).
#
# The script takes flags/options then after flags you can specify paths to
# patches to be applied.  E.g:
#   ./script -I -S 1 0001-patch 00002-patch
#
# The script first checks out the linux-next.git and all versions of the kernel
# from $MIN_KERNEL_VER on.  It then builds the kernel using defconfig + options
# returned by the local_kernel_config() callback.  After all kernels are in
# place script proceeds to tests.
#
# Script will run until it encounters the first error (see that we run bash
# with -e parameter - first command with non-zero exit status will be treated
# as error and kill the script).
#

#
# Configuration variables and callbacks
#

# Environment version
BUILD_ENV_VERSION=3
# Number of parallel builds
[ -z "$NJ" ] && NJ=$(grep processor /proc/cpuinfo | wc -l)
# Oldest kernel for which to test (in 3-digit format, 300 is 3.0, 303 is 3.3,
# 312 is 3.12, 402 is 4.2, etc.)
MIN_KERNEL_VER=308
# URL to the project repo
REPO_URL=git://source.netronome.com/nfp-drv-kmods.git
# Build directory (can get huge)
[ -z "$BUILD_ROOT" ] && BUILD_ROOT=~/tests/auto/
# Default compiler to use for most testing (must be something conservative
# otherwise the old kernels won't build).  Check if gcc-4.9, gcc-4.8 or gcc
# exist and use them in that order of priority.
[ -z "$DEFAULT_CC" ] && DEFAULT_CC=$(which gcc-4.9) || true
[ -z "$DEFAULT_CC" ] && DEFAULT_CC=$(which gcc-4.8) || true
[ -z "$DEFAULT_CC" ] && DEFAULT_CC=$(which gcc >> /dev/null && echo gcc)
# Compiler to use for building with linux-next.  You can use the lastest,
# greatest GCC here.  Leave empty to disable the extra run.
NEXT_CC=$(compgen -c gcc | sed -n '/gcc\(-[0-9]\(\.[0-9]\)*\)*$/p' | sort | tail -1)
NEXT_CC=${NEXT_CC:-$DEFAULT_CC}
# Conservative compiler which at the same time supports repolines.  GCC starting
# from version 5.
RETP_CC=$(compgen -c gcc | sed -n '/gcc-[5-9]\(\.[0-9]\)*$/p' | sort | head -1)
RETP_CC=${RETP_CC:-$DEFAULT_CC}
# ARM toolchain path
[ -z "$ARM_TOOLCHAIN" ] && ARM_TOOLCHAIN=${HOME}/cross/gcc-4.6.3-nolibc/arm-unknown-linux-gnueabi/bin/arm-unknown-linux-gnueabi-
# Silence kernel and module builds by default
SILENT=-s

source $(dirname $0)/kmod_test_patch_inc.sh

## non_vanilla_kernels() - get user-specific list of kernels to test
#
# By default we test only vanilla kernels newer or equal to $MIN_KERNEL_VER
# if you want to also build-test against other kernels (your distro kernels
# or some hand-build stuff) print the full path to the build dir in this
# function.
function non_vanilla_kernels() {
    # Sample:
    # echo /lib/modules/*/build
    # echo /path/to/my/own/kernel

    echo /lib/modules/*/build
    [ -e /CentOS7/usr/src/kernels ] && echo /CentOS7/usr/src/kernels/*/
}

## local_kernel_config() - get user-specific list of kernel config options
#
# We build the kernels with defconfig but if you want to change some of the
# default settings print them here.
function local_kernel_config() {
    echo CONFIG_MODULES=y
    echo CONFIG_SMP=y
    echo CONFIG_PCI=y
    echo CONFIG_PCI_IOV=y
    echo CONFIG_PCI_MSI=y
    echo CONFIG_NET=y
    echo CONFIG_NETDEVICES=y
    echo CONFIG_NET_SWITCHDEV=y
    echo CONFIG_NET_CORE=y
    echo CONFIG_INET=y
    echo CONFIG_VXLAN=y
    echo CONFIG_ZLIB_INFLATE=y

    # We can't select ZLIB_INFLATE directly so we need something small which
    # depends on it
    echo CONFIG_ISO9660_FS=y
    echo CONFIG_ZISOFS=y

    echo CONFIG_SPARSE_RCU_POINTER=y
    echo CONFIG_BPF_SYSCALL=y
}

## local_notify() - notify user about the results
#
# This function is run whenever script exits, results are passed to it via
# parameters.  You can use this function to hook the script into your favourite
# notification system or simply echo to the terminal (or both).
function local_notify() {
    echo -e "$@"
    notify-send "$@"
}


#################################################################################
#################################################################################
#################################################################################

call_dir=`pwd`
IGNORE_CP=0
IGNORE_XT=0
NET_HEAD="origin/master"
NET_NEXT_HEAD="origin/master"

#
# Utility functions
#
function bold() { # print in bold
    echo -e '\e[47;30m'$@'\e[0m'
}
function bold_green() { # print in bold green
    echo -e '\e[42;30m'$@'\e[0m'
}
function bold_red() { # print in bold red
    echo -e '\e[41;30m'$@'\e[0m'
}
function bold_yellow() { # print in bold yellow (foreground only)
    echo -e '\e[1;33m'$@'\e[0m'
}

function l() { # draw a horizontal line
    echo -ne "\e[30;47m"
    for i in `seq $(tput cols)`; do
	echo -n =
    done
    echo -e "\e[0m"
}

function redirect() {
    if [ -n "$SILENT" ]; then
	# By default, print only stderr, but log all output (stdout and stderr)
	$@ 2>&1 1>&3 | tee -a $BUILD_ROOT/build.log >&2
    else
	$@ 2>&1 | tee -a $BUILD_ROOT/build.log
    fi
}

#
# Functions
#

function cc_choose_retpoline() {
    grep 'RETPOLINE=y' ${1}.config >> /dev/null && \
	echo $RETP_CC || echo $DEFAULT_CC
}

# Build kernel in $1 directory
function build_kernel() {
    (
	local CC DIR

	cd $1

	[ -n "$2" ] && DIR="O=$2/"

	local_kernel_config $1 > arch/x86/configs/local_defconfig

	if [ $1 == "." -a -n "$2" ]; then
	    bold_yellow "Building in $2"
	else
	    bold_yellow "Building in $1"
	fi

	make $SILENT $DIR defconfig
	CC=`cc_choose_retpoline ${DIR:2}`

	make $SILENT $DIR CC=$CC defconfig
	make $SILENT $DIR CC=$CC local_defconfig
	make $SILENT $DIR CC=$CC -j$NJ
    )
}

# Check warning count
function check_warn_cnt() {
    current=$1
    incumbent=$2
    name=$3

    if [ $current -gt $incumbent ]; then
	bold_red "New $name warnings $current (expected: $incumbent)"
	exit 1
    elif [ $current -lt $incumbent ]; then
	bold_green "$name is now at $current warnings (was: $incumbent)"
    fi

}

# Show usage help message and exit
function usage() {
    echo -e "Usage: $0 [-h] [-I] [-b <workdir>] [-c <n>] [-s <n>] <patch> [<patch>...]"
    echo -e "\t-b <n>  build directory to use instead of default one"
    echo -e "\t-S <n>  skip testing of first <n> patchs; this is useful if you already"
    echo -e "\t        checked those patches in previous run"
    echo -e "\t-I      keep going even if checkpatch reports problems (setting this"
    echo -e "\t        flag will also make checkpatch output go to checkpatch.log)."
    echo -e "\t-X      keep going even if xmastree reports problems (setting this"
    echo -e "\t        flag will also make xmastree output go to xmastree.log)."
    echo -e "\t-c <n>  set number of incumbent cocci warnings to <n> for this run"
    echo -e "\t-s <n>  set number of incumbent sparse warnings to <n> for this run"
    echo -e "\t-d <n>  set number of incumbent kdoc warnings to <n> for this run"
    echo -e "\t-l <n>  set number of incumbent new line warnings to <n> for this run"
    echo -e "\t        NOTE: setting inclumbent errors from command line disables"
    echo -e "\t              automatic refresh of all values for each patch"
    echo -e "\t-n	net commit to build against (default origin/master)"
    echo -e "\t-N	net-next commit to build against (default origin/master)"
    echo
    echo -e "\t-v      verbose output for kernel and module builds"
    echo -e "\t-h      print help"

    trap '' EXIT
    cleanup

    exit 1
}

function cleanup {
    unset kernels
    # Close log file FD
    exec 3>&-
}

function fail_and_clean {
    local_notify "Tests failed"
    cleanup
}
trap fail_and_clean EXIT

#
# Script starts here
#

skip_check_cnt=0

# Parse options
prev_p_cnt=$#
((prev_p_cnt++))
while [ $prev_p_cnt != $# ]; do
    prev_p_cnt=$#

    [ "$1" == "-h" ] && usage
    [ "$1" == "-v" ] && SILENT="" && shift
    [ "$1" == "-b" ] && shift && BUILD_ROOT=$1 && shift
    [ "$1" == "-I" ] && shift && IGNORE_CP=1
    [ "$1" == "-X" ] && shift && IGNORE_XT=1
    [ "$1" == "-S" ] && shift && skip_check_cnt=$1 && shift
    [ "$1" == "-c" ] && shift && INCUMBENT_COCCI_WARNINGS=$1   _I=1 && shift
    [ "$1" == "-s" ] && shift && INCUMBENT_SPARSE_WARNINGS=$1  _I=1 && shift
    [ "$1" == "-d" ] && shift && INCUMBENT_KDOC_WARNINGS=$1    _I=1 && shift
    [ "$1" == "-l" ] && shift && INCUMBENT_NEWLINE_WARNINGS=$1 _I=1 && shift
    [ "$1" == "-n" ] && shift && NET_HEAD=$1		&& shift
    [ "$1" == "-N" ] && shift && NET_NEXT_HEAD=$1	&& shift
done

# By default we suppress stdout output in the console, but print both stdout
# and stderr to the log file when compiling the module. For this we need a file
# descriptor for the logs.
exec 3<>$BUILD_ROOT/build.log

# Do basic checks
[ $# -lt 1 ] && usage
[ -z "$BUILD_ROOT" ] && bold "no BUILD_ROOT specified"  &&  usage

! [ -e "$BUILD_ROOT" ] && mkdir -p $BUILD_ROOT && echo -n $BUILD_ENV_VERSION > $BUILD_ROOT/version
! [ -d "$BUILD_ROOT" ] && bold "BUILD_ROOT ($BUILD_ROOT) is not a directory" && usage

! [ -f $BUILD_ROOT/version ] && bold_red "Version file not found, assuming OK" && echo -n $BUILD_ENV_VERSION > $BUILD_ROOT/version

[ $(cat $BUILD_ROOT/version) != $BUILD_ENV_VERSION ] && bold_red "Your build directory was created with an old version of the script, you have to recreate it or fix it manually" && exit

(
    cd $BUILD_ROOT

    #
    # Prepare the environment
    #
    bold "Preparing Linux env..."
    kernels=

    # Upgrade old envs which use linux-next instead of net-next
    if [ -d "linux-next.git" ]; then
	bold "Updating old Linux env to use net trees..."

	mv linux-next.git net-next.git
	(
	    cd net-next.git/

	    git remote remove origin
	    git remote add origin git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git
	)
	rm -rf linux.git/

	mv linux-next/ net-next/
	mv linux/ net/
    fi

    ! [ -d "net-next.git" ] && git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git net-next.git
    ! [ -d "net.git" ] && git clone --reference net-next.git/ git://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git net.git

    (
	cd net-next.git/

	git fetch --all
	git checkout origin/master

	# Get non-rc version tags in 3-digit format
	kernel_3d=`git tag | sed -n 's/^v\([0-9]*\).\([0-9]*\)$/\1\2/p' | sed 's/^\([0-9]\)\([0-9]\)$/\10\2/' | sort -n`
	for tag in $kernel_3d; do
	    [ $tag -lt $MIN_KERNEL_VER ] && continue

	    # Convert 3-digit back to tag version string
	    v="v$(echo $tag | sed 's/^\(.\)0\(.\)$/\1\2/;s/^\(.\)\(.*\)$/\1.\2/')"

	    kernels="$v $kernels"

	    # Create copies of the source at different stages in time and prebuild
	    [ -d ../linux-$v ] && continue
	    git checkout $v
	    git checkout-index -a -f --prefix=../linux-$v/

	    # Fix a script that breaks compilation in 3.8
	    if [ $v == "v3.8" ]; then
		sed -i 's/if (!defined(@val))/if (!(@val))/' ../linux-$v/kernel/timeconst.pl
	    fi

	    build_kernel ../linux-$v/
	done

	git checkout $NET_NEXT_HEAD
	build_kernel . ../net-next

	#
	# Prepare 32bit build of net-next
	#
	bold_yellow "Building 32bit version of net-next"
	linux32 make $SILENT CC=$NEXT_CC O=../net-next-32bit/ ARCH=i386 defconfig
	linux32 make $SILENT CC=$NEXT_CC O=../net-next-32bit/ ARCH=i386 local_defconfig
	make $SILENT CC=$NEXT_CC O=../net-next-32bit/ ARCH=i386 -j$NJ

	#
	# Prepare net.git
	#
	cd ../net.git/
	git fetch --all
	git checkout $NET_HEAD

	build_kernel . ../net

	#
	# Prepare nfp ARM build
	#
	bold_yellow "Building nfp ARM build"
	if ! [ -e "../nfp-bsp-linux" ]; then
	    (
		cd ..
		git clone git://source.netronome.com/nfp-bsp-linux.git
		cd nfp-bsp-linux
		git checkout remotes/origin/nfp-bsp-6000-b0
		make $SILENT ARCH=arm CROSS_COMPILE=$ARM_TOOLCHAIN nfp_defconfig
		make $SILENT ARCH=arm CROSS_COMPILE=$ARM_TOOLCHAIN -j$NJ
	    )
	fi

	echo -e "kernels='$kernels'" > ../kernels
    )
    . kernels

    #
    # Install required tools
    #
    dpkg -l coccinelle sparse  > /dev/null
    if [ $? -ne 0 ]; then
	bold "Installing required tools"
	sudo apt-get install coccinelle sparse
    fi

    #
    # Prepare fresh copy of our repo
    #
    bold "Preparing repo"

    [ -d "nfp-drv-kmods" ] || git clone $REPO_URL
    (
	cd nfp-drv-kmods/
	git checkout master
	git fetch --all
	git reset --hard origin/master
    )

    l # separate the tests from prep with a line across the terminal

    rm -f checkpatch.log xmastree.log

    #
    # Test patches loop
    #
    while [ -n "$1" ]; do
	if [ ${1::1} == '/' ]; then
	    real_path=$1
	else
	    real_path=$call_dir/$1
	fi

	(
	    cd nfp-drv-kmods

	    # Always build test harness
	    export CONFIG_NFP_TEST_HARNESS=m

	    git am --abort 2>/dev/null || true
	    git am $real_path

	    # This hacky hack says - if skip_check_cnt is not 0 - skip
	    ((skip_check_cnt)) && continue

	    # Skip the patch if it doesn't modify the src directory
	    [ -z "$(git show -- src/)" ] && continue

	    # Re-read the incumbent error counts - they can change from
	    # patch to patch
	    [ -z "$_I" ] && source tools/kmod_test_patch_inc.sh

	    #
	    # Run checkpatch
	    #
	    if [ $IGNORE_CP -eq 1 ]; then
		../net-next.git/scripts/checkpatch.pl --strict $real_path 2>&1 | tee -a ../checkpatch.log
	    else
		../net-next.git/scripts/checkpatch.pl --strict $real_path
	    fi

	    #
	    # Check variable ordering
	    #
	    if [ $IGNORE_XT -eq 1 ]; then
		./tools/xmastree.py $real_path 2>&1 | tee -a ../xmastree.log
	    else
		./tools/xmastree.py $real_path
	    fi

	    #
	    # Check kerneldoc
	    #
	    rm -f src/*.mod.c || true
	    ../net-next.git/scripts/kernel-doc -none $(find -name '*.c' -or -name '*.h') 2> ../kdoc.log || true
	    sed -i '/warning: no structured comments found/d' ../kdoc.log
	    kdoc_warnings=$(cat ../kdoc.log | wc -l)
	    check_warn_cnt $kdoc_warnings $INCUMBENT_KDOC_WARNINGS kdoc

	    #
	    # Check new lines in strings
	    #
	    nl_warnings=$(grep -nrI '[^n]"[,)]' src/ | sed -e '
		/nfp_pr_et/d;
		/"AS IS"/d;
		/MODULE_/d;
		/strn*cpy/d;
		/strn*cmp/d;
		/sn*printf/d;
		/scanf/d;
		/seq_/d;
		/_phymod_get_attr_/d;
		/? ".*" *: ".*"/d;
		/debugfs_create_/d;
		/WARN/d;
		/NL_SET_ERR_MSG_MOD/d;
		/nfp_bpf_[a-z_]*_ok/d;
		/_rtsym.*(/d;
		/\[[A-Z_]*\]\s*= ".*",/d;
		/\.[a-z0-9_]*\s*= ".*",/d' | wc -l)
	    check_warn_cnt $nl_warnings $INCUMBENT_NEWLINE_WARNINGS "'line endings in strings'"

	    #
	    # Build in net-next
	    #
	    echo > ../build.log
	    bold_yellow "Building in net-next"
	    redirect make CC=$NEXT_CC -j$NJ -C ../net-next M=`pwd`/src W=1 $next_cflags
	    redirect make CC=$NEXT_CC -j$NJ -C ../net-next-32bit M=`pwd`/src W=1 $next_cflags

	    #
	    # Build in net
	    #
	    bold_yellow "Building in net"
	    redirect make CC=$NEXT_CC -j$NJ -C ../net M=`pwd`/src W=1 $next_cflags

	    #
	    # Build with different configs
	    #
	    build_opts=(CONFIG_NFP_NET_PF CONFIG_NFP_NET_VF \
			CONFIG_NFP_USER_SPACE_CPP)
	    for i in `seq $(((1 << ${#build_opts[@]}) - 1))`
	    do
		b_opts=
		for j in `seq 0 $((${#build_opts[@]} - 1))`
		do
		    [ $(($i & (1 << $j))) -eq 0 ] && continue

		    b_opts="$b_opts ${build_opts[j]}=n"
		done

		bold_yellow "Building with opts=$b_opts"
		redirect make CC=$NEXT_CC -j$NJ -C ../net-next M=`pwd`/src W=1 $next_cflags $b_opts
	    done
	    bold_yellow "Building with opts=CONFIG_NFP_TEST_HARNESS=m"
	    redirect make CC=$NEXT_CC -j$NJ -C ../net-next M=`pwd`/src W=1 $next_cflags CONFIG_NFP_TEST_HARNESS=m
	    bold_yellow "Building with opts=CONFIG_NFP_NET_PF=n CONFIG_NFP_NET_VF=n CONFIG_NFP_DEBUG=y"
	    redirect make CC=$NEXT_CC -j$NJ -C ../net-next M=`pwd`/src \
		 W=1 $next_cflags CONFIG_NFP_NET_PF=n CONFIG_NFP_NET_VF=n CONFIG_NFP_DEBUG=y

	    #
	    # Check sparse warnings
	    #
	    bold_yellow "Check sparse warnings"
	    make CC=$NEXT_CC -j$NJ -C ../net-next M=`pwd`/src C=2 CF=-D__CHECK_ENDIAN__ 2>&1 | tee ../sparse.log
	    sparse_warnings=$(grep "\(arning:\|rror:\)" ../sparse.log | wc -l)
	    check_warn_cnt $sparse_warnings $INCUMBENT_SPARSE_WARNINGS sparse

	    #
	    # Build for older kernels
	    #
	    for v in $kernels; do
		bold_yellow "Building for kernel $v"
		V_CC=`cc_choose_retpoline ../linux-$v/`
		redirect make CC=$V_CC -j$NJ -C ../linux-$v M=`pwd`/src
		redirect make CC=$V_CC -j$NJ -C ../linux-$v M=`pwd`/src clean
	    done
	    for build_dir in `non_vanilla_kernels`; do
		bold_yellow "Building for $build_dir"
		NV_CC=`cc_choose_retpoline ${build_dir}/`
		redirect make CC=$NV_CC -j$NJ -C $build_dir M=`pwd`/src
		redirect make CC=$NV_CC -j$NJ -C $build_dir M=`pwd`/src clean
	    done

	    #
	    # Build for ARM (cross-compile 3.10)
	    #
	    bold_yellow "Building for ARM"
	    redirect make ARCH=arm CROSS_COMPILE=$ARM_TOOLCHAIN -j$NJ -C ../nfp-bsp-linux M=`pwd`/src

	    build_warnings=$(grep -i "\(warn\|error\)" ../build.log | wc -l)
	    check_warn_cnt $build_warnings 0 build

	    #
	    # Run coccicheck
	    #
	    bold_yellow "Run coccicheck"
	    make CC=$DEFAULT_CC -C ../net-next M=`pwd`/src coccicheck | tee ../cocci.log
	    cocci_warnings=$(grep '^/' ../cocci.log | wc -l)
	    check_warn_cnt $cocci_warnings $INCUMBENT_COCCI_WARNINGS cocci
	)

	((skip_check_cnt)) && ((skip_check_cnt--))

	bold "All test passed for $1"
	echo
	shift
    done
)

local_notify "All tests OK!"

trap '' EXIT
cleanup
