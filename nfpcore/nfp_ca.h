/*
 * Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * NFP CPP Action trace file format
 */

#ifndef NFP_CA_H
#define NFP_CA_H

int nfp_ca_replay(struct nfp_cpp *cpp, const void *ca_buffer, size_t ca_size);

#endif /* NFP_CA_H */
/* vim: set shiftwidth=4 expandtab:  */
/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
