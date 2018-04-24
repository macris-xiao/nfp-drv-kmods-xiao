	r0 = 0

	r0 += -2
	if r0 != -2 goto bad

	r0 += -0xffffff
	if r0 != -0x1000001 goto bad

	r0 = 0xf00000000 ll

	r0 += -1
	r1 = 0xeffffffff ll
	if r0 != r1 goto bad

	r0 += 2
	r1 = 0xf00000001 ll
	if r0 != r1 goto bad

	r0 = 0

	r0 += 2
	if r0 != 2 goto bad

	r0 += 0xffffff
	if r0 != 0x1000001 goto bad

	r0 = -2

	if r0 < -2 goto bad
	if r0 > -2 goto bad

	if r0 <= -2 goto next1
	goto bad
next1:
	if r0 >= -2 goto next2
	goto bad
next2:

	if r0 s< -2 goto bad
	if r0 s> -2 goto bad

	if r0 s<= -2 goto next3
	goto bad
next3:
	if r0 s>= -2 goto next4
	goto bad
next4:

	if r0 > -1 goto bad
	if r0 < -3 goto bad
	if r0 < 1 goto bad

	if r0 >= -1 goto bad
	if r0 <= -3 goto bad
	if r0 <= 1 goto bad

	if r0 s> 1 goto bad
	if r0 s> -1 goto bad
	if r0 s< -3 goto bad

	if r0 s>= 1 goto bad
	if r0 s>= -1 goto bad
	if r0 s<= -3 goto bad

	r0 = 2
	exit
bad:
	r0 = 1
	exit
