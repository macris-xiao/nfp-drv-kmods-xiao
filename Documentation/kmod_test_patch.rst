.. Copyright (c) 2018 Netronome Systems, Inc.
.. _kmod_test_patch:

============================================
Checking patches with ``kmod_test_patch.sh``
============================================

Running the script
==================

We have an automated build script which also runs basic kernel-style checks
(tools/kmod_test_patch.sh). On the first run it will do a lot of fetches and
builds. Best to keep a separate directory dedicated to testing, by default
script will place all the files in ~/tests/auto. Before running the script make
sure you adjust the global variables to match your environment. You will need
an `ARM cross-compilation toolchain`_. Note that this script needs ~30 GB of
disk space for all the builds. Quick start::

    # apt-get install coccinelle sparse codespell
    $ ./tools/kmod_test_patch.sh /path/to/patch1 /path/to/patch2 /path/to/patch3

.. _`ARM cross-compilation toolchain`:
   https://www.kernel.org/pub/tools/crosstool/files/bin/x86_64/4.6.3/x86_64-gcc-4.6.3-nolibc_arm-unknown-linux-gnueabi.tar.xz

Note that you need to have gcc-4.9 or older on your system to build the old
kernels.

The script sometimes need to have false-positive counts adjusted (in
tools/kmod_test_patch_inc.sh). For instance the script is trying to warn about
strings not terminated with new line characters to catch invalid log messages.
If your code triggers new false positives please bump the counts as a part of
your submission.

Hint: use ``-S <n>`` to apply but not test the first ``<n>`` patches.
The ``-h`` prints a description of the other available commands::

    $ ./tools/kmod_test_patch.sh -h
    Usage: ./tools/kmod_test_patch.sh [-h] [-I] [-b <workdir>] [-c <n>] [-s <n>] <patch> [<patch>...]
            -b <n>  build directory to use instead of default one
            -S <n>  skip testing of first <n> patchs; this is useful if you already
                    checked those patches in previous run
            -I <n>  warn only on checkpatch for first <n> patches; checkpatch will
                    not error out for first <n> patches; output sent to checkpatch.log
            -X      keep going even if xmastree reports problems (setting this
                    flag will also make xmastree output go to xmastree.log).
            -c <n>  set number of incumbent cocci warnings to <n> for this run
            -s <n>  set number of incumbent sparse warnings to <n> for this run
            -d <n>  set number of incumbent kdoc warnings to <n> for this run
            -l <n>  set number of incumbent new line warnings to <n> for this run
                    NOTE: setting inclumbent errors from command line disables
                          automatic refresh of all values for each patch
            -n      net commit to build against (default origin/master)
            -N      net-next commit to build against (default origin/master)
            -K      apply patches without 'kmods' in their 'Subject:' to net-next,
                    then skip checks for those patches

            -v      verbose output for kernel and module builds
            -h      print help

Troubleshooting
===============

Too many sparse warnings
------------------------

The false-positive count for sparse assume a recent version of sparse is used.
Package repositories for main distributions are not always recent enough. If in
doubt, try the master branch from sparse Git repository::

    git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git

For example, Ubuntu 16.04 is known to propose a sparse version which is too
old.

GCC version
-----------

``kmod_test_patch.sh`` requires multiple versions of GCC to be installed
on the host.  Having GCC 4.9 and GCC 7.3 installed is recommended.

Older kernels do not support GCC version 5 and above.  You may see::

  code model kernel does not support PIC mode

or an error saying that kernel staight up doesn't know the compiler.

GCC 4.9 seems to be a good fit for older kernels.  Version 4.8 will break on
flag ``-fstack-protector-strong`` used for kernel 4.15 and above.

Newer kernels require a version of GCC which is able to generate retpolines.
Retpoline patches were backported to GCC all the way back to version 5, so
with luck GCC 5.5 is the minimal required version, but newer version like 7.3
or 8.2 is recommended.

The script should automatically pick the versions appropriate for different
kernels.

Tips
====

Running with kernel modifications
---------------------------------

Kernel developers may want to apply patches both to the driver and to the
kernel repo (net-next, typically). Note that the script offers a ``-K`` option
to do just that. When this option is passed, and before applying each patch,
the script looks at the patch ``Subject:`` line and searches for the ``kmods``
string in it.

- If ``kmods`` is in the subject, then the patch is applied to the driver code,
  and checks are performed as usual.
- If ``kmods`` is _not_ found, then the patch is applied to net-next instead.
  Then we skip all checks for that patch.

For example, imagine a patch series supposed to be sent upstream and touching
both kernel and driver, as follows:

- 1-kernel.patch, 2-kernel.patch are kernel code
- 3-nfp.patch is driver code
- 4-kernel.patch is kernel code
- 5-kernel-nfp.patch is a mix of kernel and driver code

Let's say that 3-nfp_bp.patch and 5-nfp_bp.patch are the backported patches
with just the driver code. We can test all the patches at once with this
command::

    $ ./tools/kmod_test_patch.sh -K \
            1-kernel.patch \
            2-kernel.patch \
            3-nfp.patch 3-nfp_bp.patch \
            4-kernel.patch \
            5-kernel-nfp.patch 5-nfp_bp.patch

The driver code being compiled is always the code in nfp-drv-kmods, so applying
driver patches to the net-next repo does not have any effect (other than
ensuring dependencies are met for later patches). In our example, this means
that patch 3-nfp.patch may be omitted, if 5-kernel-nfp.patch can compile
without it.

Kernel patches applied this way are not counted in the ``<n>`` first patches to
skip for the ``-S`` or ``-I`` options.
