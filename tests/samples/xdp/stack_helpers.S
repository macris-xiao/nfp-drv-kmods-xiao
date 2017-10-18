	;; STACK_INIT_SIMPLE - init stack to a known pattern via r10
	;; @_n_bytes: how many bytes to init
	.macro STACK_INIT_SIMPLE _n_bytes, _tmp_reg
		.if \_n_bytes % 32 != 0
			.error "number of bytes must be a multiple of 32"
		.endif
		.if \_n_bytes > 128
			.error "> 128B not supported"
		.endif

		\_tmp_reg = 0x1234567890abcdef ll
		*(u64 *)(r10 -  8) = \_tmp_reg
		*(u64 *)(r10 - 16) = \_tmp_reg
		\_tmp_reg = 0xfedcba0123456789 ll
		*(u64 *)(r10 - 24) = \_tmp_reg
		*(u64 *)(r10 - 32) = \_tmp_reg

		.if \_n_bytes > 32
			\_tmp_reg = 0x1234567890abcdef ll
			*(u64 *)(r10 - 40) = \_tmp_reg
			*(u64 *)(r10 - 48) = \_tmp_reg
			\_tmp_reg = 0xfedcba0123456789 ll
			*(u64 *)(r10 - 56) = \_tmp_reg
			*(u64 *)(r10 - 64) = \_tmp_reg
		.endif
		.if \_n_bytes > 64
			\_tmp_reg = 0x1234567890abcdef ll
			*(u64 *)(r10 - 72) = \_tmp_reg
			*(u64 *)(r10 - 80) = \_tmp_reg
			\_tmp_reg = 0xfedcba0123456789 ll
			*(u64 *)(r10 - 88) = \_tmp_reg
			*(u64 *)(r10 - 96) = \_tmp_reg
		.endif
		.if \_n_bytes > 96
			\_tmp_reg = 0x1234567890abcdef ll
			*(u64 *)(r10 - 104) = \_tmp_reg
			*(u64 *)(r10 - 112) = \_tmp_reg
			\_tmp_reg = 0xfedcba0123456789 ll
			*(u64 *)(r10 - 120) = \_tmp_reg
			*(u64 *)(r10 - 128) = \_tmp_reg
		.endif
	.endm

	;; STACK_INIT_CONST - init section of the stack to @const
	;; start at @_start_reg or if @_start_reg == @_ptr_reg continue
	;; with the address already in @_ptr_reg
	.macro STACK_INIT_CONST _n_bytes, _const, _ptr_reg, _tmp1, _start_reg=r10
		.if \_n_bytes % 8 != 0
			.error "number of bytes must be a multiple of 8"
		.endif

		\_tmp1 = \_const ll
		.ifnc \_start_reg, \_ptr_reg
			\_ptr_reg = \_start_reg
		.endif

		.rep \_n_bytes / 8
			\_ptr_reg += -8
			*(u64 *)(\_ptr_reg + 0) = \_tmp1
		.endr
	.endm

	;; STACK_CHECK_CONTENTS - make sure contents of the stack are @_const
	.macro STACK_CHECK_CONTENTS _n_bytes, _const, _ptr_reg, _err, _tmp1, _tmp2, _start_reg=r10
		.if \_n_bytes % 8 != 0
			.error "number of bytes must be a multiple of 8"
		.endif

		\_tmp1 = \_const ll
		.ifnc \_start_reg, \_ptr_reg
			\_ptr_reg = \_start_reg
		.endif

		.rep \_n_bytes / 8
			\_ptr_reg += -8
			\_tmp2 = *(u64 *)(\_ptr_reg + 0)
			if \_tmp1 != \_tmp2 goto \_err
		.endr
	.endm

	;; STACK_MARK_USED - make verifier think we're using @_n_bytes
	;; of the stack
	.macro STACK_MARK_USED _n_bytes
		*(u8 *)(r10 - 1) = 0
		*(u8 *)(r10 - \_n_bytes) = 0
	.endm
