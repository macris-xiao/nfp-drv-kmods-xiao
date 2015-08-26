/*
 * ************************************** 
 * 
 * Copyright 2015 Netronome Systems, Inc.
 * 
 * This software is dual licensed under the GNU General  License Version 2, June 1991
 * or the BSD 2-Clause License. The license template for each is  shown below:
 * 
 * **************************************
 * GNU GENERAL PUBLIC LICENSE
 * 
 * Version 2, June 1991
 * 
 * Copyright (C) 1989, 1991 Free Software Foundation, Inc.  
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 * 
 * Everyone is permitted to copy and distribute verbatim copies of this license document, but 
 * changing it is not allowed.
 * Preamble
 * 
 * The licenses for most software are designed to take away your freedom to share and change
 * it. By contrast, the GNU General Public License is intended to guarantee your freedom to
 * share and change free software--to make sure the software is free for all its users. This 
 * General Public License applies to most of the Free Software Foundation's software and to   
 * any other program whose authors commit to using it. (Some other Free Software 
 * Foundation software is covered by the GNU Lesser General Public License instead.) You can
 * apply it to your programs, too.
 * 
 * When we speak of free software, we are referring to freedom, not price. Our General Public
 * Licenses are designed to make sure that you have the freedom to distribute copies of free 
 * software (and charge for this service if you wish), that you receive source code or can get it if 
 * you want it, that you can change the software or use pieces of it in new free programs; and 
 * that you know you can do these things.
 * 
 * To protect your rights, we need to make restrictions that forbid anyone to deny you these 
 * rights or to ask you to surrender the rights. These restrictions translate to certain 
 * responsibilities for you if you distribute copies of the software, or if you modify it.
 * 
 * For example, if you distribute copies of such a program, whether gratis or for a fee, you must
 * give the recipients all the rights that you have. You must make sure that they, too, receive or
 * can get the source code. And you must show them these terms so they know their rights.
 * 
 * We protect your rights with two steps: (1) copyright the software, and (2) offer you this
 * license which gives you legal permission to copy, distribute and/or modify the software.
 * 
 * Also, for each author's protection and ours, we want to make certain that everyone 
 * understands that there is no warranty for this free software. If the software is modified by 
 * someone else and passed on, we want its recipients to know that what they have is not the
 * original, so that any problems introduced by others will not reflect on the original authors' 
 * reputations.
 * 
 * Finally, any free program is threatened constantly by software patents. We wish to avoid the
 * danger that redistributors of a free program will individually obtain patent licenses, in effect
 * making the program proprietary. To prevent this, we have made it clear that any patent 
 * must be licensed for everyone's free use or not licensed at all.
 * 
 * The precise terms and conditions for copying, distribution and modification follow.
 * 
 * TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 * 
 * 0. This License applies to any program or other work which contains a notice placed by the 
 * copyright holder saying it may be distributed under the terms of this General Public License. 
 * The "Program", below, refers to any such program or work, and a "work based on the 
 * Program" means either the Program or any derivative work under copyright law: that is to 
 * say, a work containing the Program or a portion of it, either verbatim or with modifications 
 * and/or translated into another language. (Hereinafter, translation is included without 
 * limitation in the term "modification".) Each licensee is addressed as "you".
 * 
 * Activities other than copying, distribution and modification are not covered by this License; 
 * they are outside its scope. The act of running the Program is not restricted, and the output 
 * from the Program is covered only if its contents constitute a work based on the Program 
 * (independent of having been made by running the Program). Whether that is true depends 
 * on what the Program does.
 * 
 * 1. You may copy and distribute verbatim copies of the Program's source code as you receive 
 * it, in any medium, provided that you conspicuously and appropriately publish on each copy 
 * an appropriate copyright notice and disclaimer of warranty; keep intact all the notices that 
 * refer to this License and to the absence of any warranty; and give any other recipients of the 
 * Program a copy of this License along with the Program.
 * 
 * You may charge a fee for the physical act of transferring a copy, and you may at your option 
 * offer warranty protection in exchange for a fee.
 * 
 * 2. You may modify your copy or copies of the Program or any portion of it, thus forming a 
 * work based on the Program, and copy and distribute such modifications or work under the 
 * terms of Section 1 above, provided that you also meet all of these conditions:
 * 
 * a) You must cause the modified files to carry prominent notices stating that you changed the 
 * files and the date of any change.
 * b) You must cause any work that you distribute or publish, that in whole or in part contains 
 * or is derived from the Program or any part thereof, to be licensed as a whole at no charge to 
 * all third parties under the terms of this License.
 * c) If the modified program normally reads commands interactively when run, you must 
 * cause it, when started running for such interactive use in the most ordinary way, to print or 
 * display an announcement including an appropriate copyright notice and a notice that there 
 * is no warranty (or else, saying that you provide a warranty) and that users may redistribute 
 * the program under these conditions, and telling the user how to view a copy of this License. 
 * (Exception: if the Program itself is interactive but does not normally print such an 
 * announcement, your work based on the Program is not required to print an announcement.)
 * 
 * These requirements apply to the modified work as a whole. If identifiable sections of that 
 * work are not derived from the Program, and can be reasonably considered independent and 
 * separate works in themselves, then this License, and its terms, do not apply to those 
 * sections when you distribute them as separate works. But when you distribute the same
 * sections as part of a whole which is a work based on the Program, the distribution of the 
 * whole must be on the terms of this License, whose permissions for other licensees extend to
 * the entire whole, and thus to each and every part regardless of who wrote it.
 * 
 * Thus, it is not the intent of this section to claim rights or contest your rights to work written 
 * entirely by you; rather, the intent is to exercise the right to control the distribution of 
 * derivative or collective works based on the Program.
 *  
 * In addition, mere aggregation of another work not based on the Program with the Program 
 * (or with a work based on the Program) on a volume of a storage or distribution medium 
 * does not bring the other work under the scope of this License.
 * 
 * 3. You may copy and distribute the Program (or a work based on it, under Section 2) in 
 * object code or executable form under the terms of Sections 1 and 2 above provided that you 
 * also do one of the following:
 * 
 * a) Accompany it with the complete corresponding machine-readable source code, which
 * must be distributed under the terms of Sections 1 and 2 above on a medium customarily 
 * used for software interchange; or,
 * b) Accompany it with a written offer, valid for at least three years, to give any third party,
 * for a charge no more than your cost of physically performing source distribution, a complete 
 * machine-readable copy of the corresponding source code, to be distributed under the terms 
 * of Sections 1 and 2 above on a medium customarily used for software interchange; or,
 * c) Accompany it with the information you received as to the offer to distribute
 * corresponding source code. (This alternative is allowed only for noncommercial distribution 
 * and only if you received the program in object code or executable form with such an offer, in 
 * accord with Subsection b above.)
 * 
 * The source code for a work means the preferred form of the work for making modifications 
 * to it. For an executable work, complete source code means all the source code for all 
 * modules it contains, plus any associated interface definition files, plus the scripts used to 
 * control compilation and installation of the executable. However, as a special exception, the 
 * source code distributed need not include anything that is normally distributed (in either 
 * source or binary form) with the major components (compiler, kernel, and so on) of the 
 * operating system on which the executable runs, unless that component itself accompanies 
 * the executable.
 * 
 * If distribution of executable or object code is made by offering access to copy from a 
 * designated place, then offering equivalent access to copy the source code from the same 
 * place counts as distribution of the source code, even though third parties are not compelled 
 * to copy the source along with the object code.
 * 
 * 4. You may not copy, modify, sublicense, or distribute the Program except as expressly
 * provided under this License. Any attempt otherwise to copy, modify, sublicense or distribute 
 * the Program is void, and will automatically terminate your rights under this License. 
 * However, parties who have received copies, or rights, from you under this License will not 
 * have their licenses terminated so long as such parties remain in full compliance.
 * 
 * 5. You are not required to accept this License, since you have not signed it. However, 
 * nothing else grants you permission to modify or distribute the Program or its derivative 
 * works. These actions are prohibited by law if you do not accept this License. Therefore, by 
 * modifying or distributing the Program (or any work based on the Program), you indicate 
 * your acceptance of this License to do so, and all its terms and conditions for copying, 
 * distributing or modifying the Program or works based on it.
 * 
 * 6. Each time you redistribute the Program (or any work based on the Program), the recipient 
 * automatically receives a license from the original licensor to copy, distribute or modify the
 * Program subject to these terms and conditions. You may not impose any further restrictions 
 * on the recipients' exercise of the rights granted herein. You are not responsible for enforcing
 * compliance by third parties to this License.
 * 
 * 7. If, as a consequence of a court judgment or allegation of patent infringement or for any 
 * other reason (not limited to patent issues), conditions are imposed on you (whether by 
 * court order, agreement or otherwise) that contradict the conditions of this License, they do
 * not excuse you from the conditions of this License. If you cannot distribute so as to satisfy 
 * simultaneously your obligations under this License and any other pertinent obligations, then 
 * as a consequence you may not distribute the Program at all. For example, if a patent license 
 * would not permit royalty-free redistribution of the Program by all those who receive copies 
 * directly or indirectly through you, then the only way you could satisfy both it and this 
 * License would be to refrain entirely from distribution of the Program.
 * 
 * If any portion of this section is held invalid or unenforceable under any particular 
 * circumstance, the balance of the section is intended to apply and the section as a whole is 
 * intended to apply in other circumstances.
 * 
 * It is not the purpose of this section to induce you to infringe any patents or other property 
 * right claims or to contest validity of any such claims; this section has the sole purpose of 
 * protecting the integrity of the free software distribution system, which is implemented by 
 * public license practices. Many people have made generous contributions to the wide range 
 * of software distributed through that system in reliance on consistent application of that 
 * system; it is up to the author/donor to decide if he or she is willing to distribute software 
 * through any other system and a licensee cannot impose that choice.
 * 
 * This section is intended to make thoroughly clear what is believed to be a consequence of 
 * the rest of this License.
 * 
 * 8. If the distribution and/or use of the Program is restricted in certain countries either by 
 * patents or by copyrighted interfaces, the original copyright holder who places the Program 
 * under this License may add an explicit geographical distribution limitation excluding those 
 * countries, so that distribution is permitted only in or among countries not thus excluded. In
 * such case, this License incorporates the limitation as if written in the body of this License.
 * 
 * 9. The Free Software Foundation may publish revised and/or new versions of the General 
 * Public License from time to time. Such new versions will be similar in spirit to the present 
 * version, but may differ in detail to address new problems or concerns.
 * 
 * Each version is given a distinguishing version number. If the Program specifies a version 
 * number of this License which applies to it and "any later version", you have the option of 
 * following the terms and conditions either of that version or of any later version published by 
 * the Free Software Foundation. If the Program does not specify a version number of this 
 * License, you may choose any version ever published by the Free Software Foundation.
 * 
 * 10. If you wish to incorporate parts of the Program into other free programs whose 
 * distribution conditions are different, write to the author to ask for permission. For software
 * which is copyrighted by the Free Software Foundation, write to the Free Software 
 * Foundation; we sometimes make exceptions for this. Our decision will be guided by the two
 * goals of preserving the free status of all derivatives of our free software and of promoting 
 * the sharing and reuse of software generally.
 * 
 * NO WARRANTY
 * 
 * 11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR 
 * THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN 
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES 
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR 
 * IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE 
 * QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM 
 * PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR 
 * CORRECTION.
 * 
 * 12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL 
 * ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE 
 * THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY 
 * GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE 
 * OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR 
 * DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR 
 * A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH 
 * HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 
 * **************************************
 * The BSD 2-Clause License: 
 * Copyright 2015 Netronome Systems, Inc.
 * All rights reserved.
 *  
 * Redistribution and use in source and binary forms, with or without modification, are 
 * permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of 
 * conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of 
 * conditions and the following disclaimer in the documentation and/or other materials 
 * provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * *****************************************
 */

/*
 * crc32.c
 * Adapted from the POSIX manual page for cksum:
 * http://www.opengroup.org/onlinepubs/009695399/utilities/cksum.html
 */

#include <linux/kernel.h>

#include "crc32.h"

/* NOTE: This is not 'const', so that it will be relocated
 *       into RAM for speed
 *
 * Polynomial: X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+
 *             X^8+X^7+X^5+X^4+X^2+X^1+X^0
 */
static unsigned long crctab_posix[] = {
	0x00000000,
	0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
	0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6,
	0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
	0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac,
	0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8, 0x6ed82b7f,
	0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a,
	0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
	0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58,
	0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033,
	0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027, 0xddb056fe,
	0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
	0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4,
	0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
	0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5,
	0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
	0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 0x7897ab07,
	0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c,
	0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1,
	0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
	0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b,
	0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698,
	0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d,
	0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
	0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 0xc6bcf05f,
	0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
	0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80,
	0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
	0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a,
	0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e, 0x21dc2629,
	0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c,
	0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
	0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e,
	0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65,
	0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601, 0xdea580d8,
	0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
	0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2,
	0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
	0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74,
	0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
	0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 0x7b827d21,
	0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a,
	0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e, 0x18197087,
	0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
	0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d,
	0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce,
	0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb,
	0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
	0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 0x89b8fd09,
	0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
	0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf,
	0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

/**
 * crc32_posix_add() - Append data to a POSIX CRC32 calculation
 * @crc32:	Current CRC32 working state (initialize as 0)
 * @buff:	Pointer to buffer of data to add
 * @len:	Size of buffer
 *
 * Return: New CRC32 working state
 */
uint32_t crc32_posix_add(uint32_t crc32, const void *buff, size_t len)
{
	const uint8_t *b = buff;
	size_t i;

	for (i = 0; i < len; i++, b++)
		crc32 = crctab_posix[((crc32 >> 24) ^ *b) & 0xff] ^
							(crc32 << 8);

	return crc32;
}

/**
 * crc32_posix_end() - Finalize POSIX CRC32 working state
 * @crc32:	Current CRC32 working state
 * @total_len:	Total length of data that was CRC32'd
 *
 * Return: Final POSIX CRC32 value
 */
uint32_t crc32_posix_end(uint32_t crc32, size_t total_len)
{
	/* Extend with the length of the string. */
	while (total_len != 0) {
		uint8_t c = total_len & 0xff;

		crc32 = crc32_posix_add(crc32, &c, 1);
		total_len >>= 8;
	}
	return ~crc32;
}

/**
 * crc32_gb() - Gary S. Brown's 32 bit CRC algorithm
 * @crc32:	Current CRC32 working state (initialize as 0)
 * @buff:	Pointer to buffer of data to add
 * @len:	Size of buffer
 *
 * This is the standard Gary S. Brown's 32 bit CRC algorithm, but
 * accumulate the CRC into the result of a previous CRC.
 * We can use the POSIX CRC table, but realize we need to
 * reflect the input and output. This adds some overhead, but
 * it saves on space.
 *
 * Return: New CRC32 working state
 */
uint32_t crc32_gb(uint32_t crc32, const void *buff, size_t len)
{
	int i, j;
	const uint8_t *s = buff;

	for (i = 0; i < len; i++) {
		uint8_t c, v;
		uint32_t te, tc;

		v = (crc32 ^ s[i]) & 0xff;
		c = 0;
		for (j = 0; j < 8; j++)
			c |= ((v >> j) & 1) << (7 - j);

		te = crctab_posix[c];
		tc = 0;
		for (j = 0; j < 32; j++)
			tc |= ((te >> j) & 1) << (31 - j);

		crc32 = tc ^ (crc32 >> 8);
	}

	return crc32;
}
