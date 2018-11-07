##
## Copyright (C) 2018,  Netronome Systems, Inc.  All rights reserved.
##
"""
Checks on code generated by the JIT-compiler
"""

import os
import re

from netro.testinfra.nti_exceptions import NtiError
from netro.testinfra import LOG_sec, LOG, LOG_endsec

class JitCodegenCheck(object):
    """A class implementing checks on the instructions generated by the
    JIT-compiler. Those checks consist in searching for the presence or absence
    of one or several occurences of given patterns, to ensure that the desired
    instructions have been produced by the compiler.
    """
    def __init__(self, dut):
        """
        @dut: A tuple of System and interface name where to perform the check
        """
        self.dut = dut

    def get_bpf_jit_results(self):
        _, prog_id = self.dut.cmd('bpftool prog list | grep ^[0-9]*: | cut -d : -f1 | tail -1 | tr -d "\\n"')
        _, out = self.dut.cmd('bpftool prog dump jited id %s 2>&1' %(prog_id))

        return "".join(out).split("\n")

    def collect_bpf_jit_patterns(self, pattern_file=None):
        """
        Currently, three MATCH_KEY_WORD are supported:

          CHECK-CODEGEN: the specified pattern exist.
          CHECK-CODEGEN-TIMES-N: the specified pattern exist, but only shown
                                 up for N times.
          CHECK-CODEGEN-NOT: the specified pattern does not exist.

        The match rule will be recognized by the following syntax:

          /* MATCH_KEY_WORD: [regexp in the syntax of python RE library] */

        For example:

          /* CHECK-CODEGEN: .*local_csr_rd */
          /* CHECK-CODEGEN-TIMES-2: .*local_csr_rd */
          /* CHECK-CODEGEN-NOT: .*mem\[write32_swap.*8\].* */
        """
        inc_rules = []
        ext_rules = []

        if pattern_file is None:
            return inc_rules, ext_rules

        lines = open(pattern_file, "r")
        for line in lines:
            m = re.match("^\s*/\*\s*CHECK-CODEGEN: (.*)\s*\*/", line)
            if m:
                inc_rules.append((m.group(1).strip(), 0))
            else:
                m = re.match("^\s*/\*\s*CHECK-CODEGEN-NOT: (.*)\s*\*/", line)
                if m:
                    ext_rules.append(m.group(1).strip())
                else:
                    m = re.match("^\s*/\*\s*CHECK-CODEGEN-TIMES-([0-9]*): (.*)\s*\*/",
                                 line)
                    if m:
                        inc_rules.append((m.group(2).strip(), m.group(1)))

        return inc_rules, ext_rules

    def scan_bpf_jit_results(self, results, includes, excludes):
        errors = []
        for line in results:
            for e in excludes:
                m = re.match(e, line)
                if m:
                    errors.append("Unexpected pattern found: " + e + "\n")

        for i in includes:
            match_count = 0
            for line in results:
                m = re.match(i[0], line)
                if m:
                    match_count += 1
            if match_count == 0 and i[1] == 0:
                errors.append("Expected pattern not found " + i[0] + "\n")
            elif match_count != int(i[1]) and i[1] != 0:
                errors.append("Expected pattern not found " + i[1] + \
                              " times: " + i[0] + "\n")

        return "".join(errors)

    def check(self, source_file):
        includes, excludes = self.collect_bpf_jit_patterns(source_file)
        if not includes and not excludes:
            return

        LOG_sec('JIT codegen scan checks')
        try:
            jit_res = self.get_bpf_jit_results()
            if jit_res is None:
                raise NtiError("Can't find JIT codegen output")
            elif "support for NFP" in "".join(jit_res):
                LOG_sec('No Support')
                LOG('JIT codegen scan checks disabled due to no NFP support in bpftool/libbfd')
                LOG_endsec()
                return

            errors = self.scan_bpf_jit_results(jit_res, includes, excludes)
            if errors is not "":
                raise NtiError("JIT codegen scan:\n" + errors)
        finally:
            LOG_endsec()

    def get_ext_source_name(self, test, extension):
        """A method to get the source file to search for codegen checks
        patterns. From the object file used by the test, deduce the name of the
        associated source file with the given extension. Search fist the
        directory with XDP samples, fall back on BPF samples.

        @test:      A CommonTest instance for which to find the source file
        @extension: The file extension to search for
        """
        if test.group.xdp_mode() == "drv":
            return None
        prog_name = test.get_prog_name()
        filename = os.path.join(test.group.samples_xdp,
                                os.path.splitext(prog_name)[0] + extension)
        if not os.path.isfile(filename):
            filename = os.path.join(test.group.samples_bpf,
                                    os.path.splitext(prog_name)[0] + extension)
        return filename

    def get_source_name(self, test):
        """A  method to get the source file to search for codegen checks
        patterns. From the object file used by the test, try to identify first
        a C file, or fall back to an assembly (.S) file. Search fist the
        directory with XDP samples, fall back on BPF samples.

        @test:  A CommonTest instance for which to find the source file
        """
        filename = self.get_ext_source_name(test, ".c")
        if not os.path.isfile(filename):
            filename = self.get_ext_source_name(test, ".S")
        return filename
