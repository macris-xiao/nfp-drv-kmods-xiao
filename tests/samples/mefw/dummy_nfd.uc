// A very simplistic and bare NFD stub firmware
// Source was obtained from NIC-432, thanks to Edwin Peer

.alloc_mem _pf0_net_bar0 emem0 global 65536 8192

#define NFP_NET_CFG_UPDATE              0x0004
#define NFP_NET_CFG_VERSION             0x0030
#define NFP_NET_CFG_MAX_TXRINGS_0       0x003c
#define NFP_NET_CFG_MAX_RXRINGS_0       0x0040
#define NFP_NET_CFG_MAX_TXRINGS_1       0x803c
#define NFP_NET_CFG_MAX_RXRINGS_1       0x8040

.init _pf0_net_bar0+NFP_NET_CFG_VERSION 0x305
.init _pf0_net_bar0+NFP_NET_CFG_MAX_TXRINGS_0 1
.init _pf0_net_bar0+NFP_NET_CFG_MAX_RXRINGS_0 1
.init _pf0_net_bar0+NFP_NET_CFG_MAX_TXRINGS_1 1
.init _pf0_net_bar0+NFP_NET_CFG_MAX_RXRINGS_1 1

.alloc_mem nfd_cfg_pf0_num_ports emem0 global 4 256
.init nfd_cfg_pf0_num_ports             NUM_DUMMY_PORTS

.reg addr
.reg offset
.reg tmp
.reg $zero

immed[addr, ((_pf0_net_bar0 >> 8) & 0xffff)]
immed_w1[addr, (_pf0_net_bar0 >> 24)]
immed[$zero, 0]
.sig sig_write

forever#:

immed[offset, NFP_NET_CFG_UPDATE]
mem[write32, $zero, addr, <<8, offset, 1], ctx_swap[sig_write]
immed[tmp, 0x8000]
alu[offset, offset, +, tmp]
mem[write32, $zero, addr, <<8, offset, 1], ctx_swap[sig_write]

br[forever#]
