	r0 = 17

	if r0 < 0 goto bad
	if r0 < 16 goto bad
	if r0 < 17 goto bad
	if r0 > 17 goto bad
	if r0 > 18 goto bad

	if r0 <= 0 goto bad
	if r0 <= 15 goto bad
	if r0 <= 16 goto bad
	if r0 >= 18 goto bad
	if r0 >= 19 goto bad

	if r0 != 17 goto bad
	if r0 == 16 goto bad
	if r0 == 18 goto bad

	if r0 >= 0xffffffff goto bad
	if r0 > 0xffffffff goto bad


	r1 = 0
	if r0 < r1 goto bad
	r1 = 16
	if r0 < r1 goto bad
	r1 = 17
	if r0 < r1 goto bad
	if r0 > r1 goto bad
	r1 = 18
	if r0 > r1 goto bad

	r1 = 0
	if r0 <= r1 goto bad
	r1 = 15
	if r0 <= r1 goto bad
	r1 = 16
	if r0 <= r1 goto bad
	r1 = 18
	if r0 >= r1 goto bad
	r1 = 19
	if r0 >= r1 goto bad

	r1 = 17
	if r0 != r1 goto bad
	r1 = 16
	if r0 == r1 goto bad
	r1 = 18
	if r0 == r1 goto bad

	r1 = 0xffffffff
	if r0 >= r1 goto bad
	r1 = 0xffffffff
	if r0 > r1 goto bad

	r0 = 0
	if r0 < 0 goto bad
	if r0 > 0 goto bad
	if r0 > 1 goto bad
	if r0 >= 1 goto bad

	if r0 < r0 goto bad
	if r0 > r0 goto bad

	r0 = 2
	exit
bad:
	r0 = 1
	exit
