#!/bin/bash

declare -A INTRO
INTRO[low]=""
INTRO[mid]="
	r0 = 0
	*(u32 *)(r10 - 48) = r0
"
INTRO[hig]="
	r0 = 0
	*(u32 *)(r10 - 80) = r0
"

for d in ${!INTRO[@]}; do
    for i in 1 2 4 8; do
	FILE=stack_write_unaligned_$d$i.S

	rm -f $FILE

	cat > $FILE <<EOF
${INTRO[$d]}
	.include "stack_write_unaligned.S"

	TEST 0x7766554433221100, $((i * 8))
EOF
    done
done

for d in ${!INTRO[@]}; do
    for i in 1 2 4 8; do
	FILE=stack_read_unaligned_$d$i.S

	rm -f $FILE

	MASK=$(printf "0x%x" $(((1 << i * 8) - 1)))
	[ $MASK == "0x0" ] && MASK="0xffffffffffffffff"

	cat > $FILE <<EOF
${INTRO[$d]}
	.include "stack_read_unaligned.S"

	TEST 0x7766554433221100, 0xffeeddccbbaa9988, u$((i * 8)), $MASK
EOF
    done
done
