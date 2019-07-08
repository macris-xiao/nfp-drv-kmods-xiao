.. Copyright (c) 2019 Netronome Systems, Inc.
.. _patchwork:

======================
Working with Patchwork
======================

The Patchwork instance
======================

To sort and keep track of the patches submitted to the internal mailing list,
we have set up a Patchwork instance. It is available at
http://patchwork.netronome.com/project/nfp-drv-dev/list/.

The instance is currently administered by Kuba and Quentin.

Patchwork keeps track of the patches for us and presents a list of all patches
sent to the mailing list. It updates them with tags (``Reviewed-by:`` etc.) and
comments sent for those patches, and allows users to update the state of the
patches (``new``, ``under review``, ``changes requested``, etc.).

Since the instance was upgraded to version 2.1, it also supports automated
checks. For example, we now have checkpatch and xmastree.py being run
automatically on all incoming patches. This checks help for the review, but of
course they should not deter developers from running checkpatch and all other
checks on their own setup *before* posting the patches.

Getting an account
==================

An account is not necessary for reading patches on the Patchwork web interface,
or for downloading them.

However, one does need an account to update the patch status on the web
interface, or to create "bundles" (groups of patches). An account is also
required for using the REST API offered by Patchwork, hence to use the
``git-pw`` utility.

For obtaining an account on Patchwork, ask to one of the administrators.

Patchwork process
=================

All patches sent to the nfp-drv-dev mailing list are caught by Patchwork (there
might be a few delay for the update, although it should not exceed three
minutes), so basically every developer can get their patches in.

At the moment, patch status update is done by Kuba only, on a regular basis.
Please do **not** attempt to update patch status without contacting him first,
in order to avoid unexpected status changes that could result in longer
processing.

Patch status update is performed as "best effort", so be aware that statuses
may not be always up-to-date.

Command-line tool: git-pw
=========================

Patchwork provides a (legacy) XML-RPC API, and a (newer) REST API. There are
two official tools leveraging those APIs, and enabling patch manipulation from
the command line. It looks like ``pwclient`` is the oldest one, and ``git-pw``
seems to be the reference now, although  Patchwork documentation is not really
clear on the matter. As ``git-pw`` is simple to use and cover most needs, we
will focus on this one. For the full documentation, as well as for
installation instructions, please refer to `git-pw official documentation`_.

.. _git-pw official documentation:
   https://patchwork.readthedocs.io/projects/git-pw/en/latest/

Configuration
~~~~~~~~~~~~~

To use ``git-pw``, it is necessary to tell it where to look for data on the
patches. The tool gets its configuration from git, so you can configure it like
this::

    $ git config pw.server http://patchwork.netronome.com/api/1.1
    $ git config pw.project nfp-drv-dev
    $ git config pw.token <your API token>

Alternatively, you can pass the parameters through command line options, or
environment variables. Please refer to the official documentation for details.

The API token should be generated from your profile page on Patchwork. This
means you must have a Patchwork account to use ``git-pw``.

Usage
~~~~~

``git-pw`` allows users to manipulate patches, series or bundles. In
particular, one can list patches or series, and automagically download and
apply them to their repository.

For example, try the following command to list the series loaded in Patchwork::

    $ git-pw series list

Note the ids on the first column. Then if you are in a git repository,
downloading and applying (``git am``) a set is as simple as::

    $ git-pw series apply <id>

The same commands work with individual patches, so for example you can try::

    $ git-pw patch list

However, there seems to be a bug for listing patches (not sure if it comes from
``git-pw``, Patchwork, or our particular Patchwork setup). By default,
``git-pw`` tries to list all patches in the states ``new`` or ``under-review``.
But the request it sends is interpreted as states ``new`` **and**
``under-review`` at the same time, which returns an empty array, of course. It
is possible to work around the issue by explicitly requesting patches for just
one state::

    $ git-pw patch list --state new

Please refer to
`the official documentation <https://patchwork.readthedocs.io/projects/git-pw/en/latest/usage/>`_
for a full description of all available commands and options.

Notes
~~~~~

Note that ``git-pw`` can also be used with other Patchwork servers and
projects, such as
`the one for netdev <https://patchwork.ozlabs.org/project/netdev/list/>`_

Adding a new project to Patchwork
=================================

Although nfp-drv-dev is the only project to use the Patchwork instance as of
this writing, it is possible for new projects to be added as well. Adding a new
"project" (basically, track patches from another mailing list) requires two
steps:

- One of the administrators for Patchwork must create the new project in
  Django's administration console, with the relevant name and mailing list
  information.

- The email account ``patchwork@netronome.com`` must be subscribed to the
  mailing list related to that project.

Patchwork installation
======================

This is a note for Patchwork administrators or anyone willing to recreate a
Patchwork instance. As a complement to the official Patchwork documentation,
some notes on the installation of our Patchwork instance are available in the
/root/README.md file on patchwork.netronome.com, and mirrored on
https://docs.google.com/document/d/1SuCTJR4_KllZKVWQ94RNN3zk-I7FKjmgjOZNI6sFq_Q.
