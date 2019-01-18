	// JEQ
	r0 = 0x100000002 ll
	if w0 == 0x2 goto ok0
	goto bad
ok0:
	r1 = 0x100000002 ll
	if w0 == w1 goto ok1
	goto bad
ok1:

	// JNE
	r0 = 0x100000002 ll
	if w0 != 0x2 goto bad
	r1 = 0x200000002 ll
	if w0 != w1 goto bad

	// JGT
	r0 = 0x200000002 ll
	if w0 > 0x1 goto ok2
	goto bad
ok2:
	r1 = 0x100000001 ll
	if w0 > w1 goto ok3
	goto bad
ok3:

	// JLT
	r0 = 0x200000001 ll
	if w0 < 0x2 goto ok4
	goto bad
ok4:
	r1 = 0x100000002 ll
	if w0 < w1 goto ok5
	goto bad
ok5:

	// JGE
	r0 = 0x300000003 ll
	if w0 >= 0x3 goto ok6
	goto bad
ok6:
	r1 = 0x400000002 ll
	if w0 >= w1 goto ok7
	goto bad
ok7:

	// JLE
	r0 = 0x200000002 ll
	if w0 <= 0x2 goto ok8
	goto bad
ok8:
	r1 = 0x100000003 ll
	if w0 <= w1 goto ok9
	goto bad
ok9:

	// JSGT
	r0 = 0x200000003 ll
	if w0 s> 0x2 goto ok10
	goto bad
ok10:
	r1 = 0x300000002 ll
	if w0 s> w1 goto ok11
	goto bad
ok11:
	r0 = 0x2fffffffd ll
	if w0 s> -4 goto ok12
	goto bad
ok12:
	r1 = 0x3fffffffc ll
	if w0 s> w1 goto ok13
	goto bad
ok13:

	// JSLT
	r0 = 0x200000001 ll
	if w0 s< 0x2 goto ok14
	goto bad
ok14:
	r1 = 0x300000002 ll
	if w0 s< w1 goto ok15
	goto bad
ok15:
	r0 = 0x2fffffffd ll
	if w0 s< -2 goto ok16
	goto bad
ok16:
	r1 = 0x1fffffffe ll
	if w0 s< w1 goto ok17
	goto bad

ok17:
	// JSGE
	r0 = 0x300000003 ll
	if w0 s>= 0x3 goto ok18
	goto bad
ok18:
	r1 = 0x400000002 ll
	if w0 s>= w1 goto ok19
	goto bad
ok19:
	r0 = 0x3fffffffd ll
	if w0 s>= -3 goto ok20
	goto bad
ok20:
	r1 = 0x4fffffffc ll
	if w0 s>= w1 goto ok21
	goto bad
ok21:

	// JSLE
	r0 = 0x200000001 ll
	if w0 s<= 0x2 goto ok22
	goto bad
ok22:
	r1 = 0x100000001 ll
	if w0 s<= w1 goto ok23
	goto bad
ok23:
	r0 = 0x2fffffffe ll
	if w0 s<= -2 goto ok24
	goto bad
ok24:
	r1 = 0x1ffffffff ll
	if w0 s<= w1 goto ok25
	goto bad
ok25:

	r0 = 2
	exit
bad:
	r0 = 1
	exit
