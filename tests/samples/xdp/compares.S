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

	r0 = 17

	if r0 s< -1 goto bad
	if r0 s< 0 goto bad
	if r0 s< 16 goto bad
	if r0 s< 17 goto bad
	if r0 s> 17 goto bad
	if r0 s> 18 goto bad

	if r0 s<= -1 goto bad
	if r0 s<= 0 goto bad
	if r0 s<= 15 goto bad
	if r0 s<= 16 goto bad

	if r0 s>= 18 goto bad
	if r0 s>= 19 goto bad

	r1 =  0x80ffff0000000000 ll
	if r0 s<= r1 goto bad
	if r0 s< r1 goto bad

	r1 = 0x0ffff0000000000 ll
	if r0 s>= r1 goto bad
	if r0 s> r1 goto bad
	r1 = -1
	if r0 s< r1 goto bad
	r1 = 0
	if r0 s< r1 goto bad
	r1 = 16
	if r0 s< r1 goto bad
	r1 = 17
	if r0 s< r1 goto bad
	if r0 s> r1 goto bad
	r1 = 18
	if r0 s> r1 goto bad

	r1 = -1
	if r0 s<= r1 goto bad
	r1 = 0
	if r0 s<= r1 goto bad
	r1 = 15
	if r0 s<= r1 goto bad
	r1 = 16
	if r0 s<= r1 goto bad
	r1 = 18
	if r0 s>= r1 goto bad
	r1 = 19
	if r0 s>= r1 goto bad
	r0 = 0
	if r0 s< -1 goto bad
	if r0 s< 0 goto bad
	if r0 s> 0 goto bad
	if r0 s> 1 goto bad
	if r0 s>= 1 goto bad
	if r0 s< r0 goto bad
	if r0 s> r0 goto bad

	r0 = -17

	if r0 s< -18 goto bad
	if r0 s< -17 goto bad
	if r0 s> -17 goto bad
	if r0 s> -16 goto bad
	if r0 s> 0 goto bad
	if r0 s> 1 goto bad

	if r0 s<= -19 goto bad
	if r0 s<= -18 goto bad
	if r0 s>= -16 goto bad
	if r0 s>= -15 goto bad
	if r0 s>= 0 goto bad
	if r0 s>= 1 goto bad

	r1 =  0x80ffff0000000000 ll
	if r0 s<= r1 goto bad
	if r0 s< r1 goto bad

	r1 = 0x0ffff0000000000 ll
	if r0 s>= r1 goto bad
	if r0 s> r1 goto bad

	r1 = -18
	if r0 s< r1 goto bad
	r1 = -17
	if r0 s< r1 goto bad
	if r0 s> r1 goto bad
	r1 = -16
	if r0 s> r1 goto bad
	r1 = 0
	if r0 s> r1 goto bad
	r1 = 1
	if r0 s> r1 goto bad

	r1 = -19
	if r0 s<= r1 goto bad
	r1 = -18
	if r0 s<= r1 goto bad
	r1 = -16
	if r0 s>= r1 goto bad
	r1 = -15
	if r0 s>= r1 goto bad
	r1 = 0
	if r0 s>= r1 goto bad
	r1 = 1
	if r0 s>= r1 goto bad

	r0 = 17

	r1 = 16
	if r0 s> r1 goto next0a
	goto bad
next0a:
	r1 = 0
	if r0 s> r1 goto next0b
	goto bad
next0b:
	r1 = -1
	if r0 s> r1 goto next0c
	goto bad
next0c:
	r1 = 18
	if r0 s< r1 goto next1a
	goto bad
next1a:
	r1 = 17
	if r0 s>= r1 goto next2a
	goto bad
next2a:
	r1 = 16
	if r0 s>= r1 goto next2b
	goto bad
next2b:
	r1 = 0
	if r0 s>= r1 goto next2c
	goto bad
next2c:
	r1 = -1
	if r0 s>= r1 goto next2d
	goto bad
next2d:
	r1 = 18
	if r0 s<= r1 goto next3a
	goto bad
next3a:
	r1 = 17
	if r0 s<= r1 goto next3b
	goto bad
next3b:
	r0 = 0x0ffff00000000000 ll

	r1 = 0x0efff00000000000 ll
	if r0 s> r1 goto next4a
	goto bad
next4a:
	r1 = 0x0000000000000110 ll
	if r0 s> r1 goto next4b
	goto bad
next4b:
	r1 = 0x8efff0000000f000 ll
	if r0 s> r1 goto next4c
	goto bad
next4c:
	r1 = 0x7ffff00000000000 ll
	if r0 s< r1 goto next5a
	goto bad
next5a:
	r1 = 0x0ffff00000000000 ll
	if r0 s>= r1 goto next6a
	goto bad
next6a:
	r1 = 0x0efff00000000000 ll
	if r0 s>= r1 goto next6b
	goto bad
next6b:
	r1 = 0x0000000000000000 ll
	if r0 s>= r1 goto next6c
	goto bad
next6c:
	r1 = 0x8efff0000000f000 ll
	if r0 s>= r1 goto next6d
	goto bad
next6d:
	r1 = 0x0ffff00000000000 ll
	if r0 s<= r1 goto next7a
	goto bad
next7a:
	r1 = 0x7ffff00000000000 ll
	if r0 s<= r1 goto next7b
	goto bad
next7b:

	r0 = 2
	exit
bad:
	r0 = 1
	exit
