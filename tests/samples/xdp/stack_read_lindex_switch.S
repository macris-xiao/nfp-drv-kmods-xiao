# LM_addr could be used as base of a 16 32-bit word region of Local Memory.
# Then, if the stack offset is beyond the current region, the local index
# needs to be updated. The update needs at least three cycles to take effect,
# therefore the sequence normally looks like:
#
#   local_csr_wr[ActLMAddr3, gprB_5]
#   nop
#   nop
#   nop
#
# If the local index switch happens on a narrow loads, then the instruction
# preparing value to zero high 32-bit of the destination register could be
# counted as one cycle, the sequence then could be something like:
#
#   local_csr_wr[ActLMAddr3, gprB_5]
#   nop
#   nop
#   immed[gprB_5, 0]
#
# However, we have zero extension optimization that zeroing high 32-bit could
# be eliminated, therefore above IMMED insn won't be available for which case
# the first sequence needs to be generated.
#
# This testcase makes sure correct sequence generated when there is zero
# extension optimization.

	.include "xdp.S"
	r0 = 0
	*(u32 *)(r10 - 160) = r0
	r0 = 0x7766554433221100 ll
	*(u64 *)(r10 - 80) = r0
	r0 = 0xffeeddccbbaa9988 ll
	*(u64 *)(r10 - 8) = r0
	# a narrow loads and it trigger local index switch.
	w2 = *(u32 *)(r10 - 80)
	if w2 != 0x33221100 goto bad
	r0 = XDP_PASS
	exit
bad:
	r0 = XDP_DROP
	exit
