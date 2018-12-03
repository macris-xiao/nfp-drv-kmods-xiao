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
            -I      keep going even if checkpatch reports problems (setting this
                    flag will also make checkpatch output go to checkpatch.log).
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

Gcc version
-----------

Gcc 4.9 seems to be the only tool able to compile successfully all kernels.
Version 4.8 will break on flag ``-fstack-protector-strong`` used for kernel
4.15 and above, while newer gcc have trouble with the old kernels.
