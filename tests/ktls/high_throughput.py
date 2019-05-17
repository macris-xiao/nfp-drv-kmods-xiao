#
# Copyright (C) 2019,  Netronome Systems, Inc.  All rights reserved.
#

from .base_traffic import KTLSTrafficTestBase

class KTLSHighThroughput(KTLSTrafficTestBase):
    def execute(self):
        return self.run_traffic_test(10000, 10000)
