.. Copyright (c) 2018 Netronome Systems, Inc.
.. _kmod_test_patch:

============================================
Checking patches with ``kmod_test_patch.sh``
============================================

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
