#!/usr/bin/env python3

empty = "0_null.c"
src_dir = "synthetic_blocks/"
masklist= ['0xFF', '0xFFF', '0xFFFF', '0x7FFFF']

def copyfile(src_file, outfile):
    with open(src_file) as infile:
        for line in infile:
            outfile.write(line)

def createfiles(mask, blocknum, memlookups, atomic, filename):
        start_filename = ["0_start.c"]
        filenames = [
             "1_optional2.c",
             "2_ipheader.c",
             "3_map1.c",
             "4_optional3.c",
             "5_map2.c",
             "6_tcp.c",
             "7_map3.c",
             "8_option4.c",
             "9_option5.c",
             "a_map4.c",
             "b_pktextend.c"
            ]

        # REMOVE MAP LOOKUPS THAT AREN'T REQUIRED
        if memlookups is 1:
            filenames[2] = empty
            filenames[4] = empty
            filenames[6] = empty
            filenames[9] = empty
        elif memlookups is 2:
            filenames[4] = empty
            filenames[6] = empty
            filenames[9] = empty
        elif memlookups is 3:
            filenames[6] = empty
            filenames[9] = empty
        elif memlookups is 4:
            filenames[9] = empty

        # REMOVE BLOCK FILES THAT AREN'T REQUIRED
        if blocknum is 0:
            filenames[10] = empty
            filenames[0] = empty
            filenames[3] = empty
            filenames[7] = empty
            filenames[8] = empty
        elif blocknum is 1:
            filenames[0] = empty
            filenames[3] = empty
            filenames[7] = empty
            filenames[8] = empty
        elif blocknum is 2:
            filenames[3] = empty
            filenames[7] = empty
            filenames[8] = empty
        elif blocknum is 3:
            filenames[7] = empty
            filenames[8] = empty
        elif blocknum is 4:
            filenames[8] = empty
        elif blocknum is 5:
            pass

        map_size = int(mask, 16) + 1

        outfile = open(filename, 'w')
        outfile.write("#define MAXENTRIES %s\n" % map_size)
        outfile.write("#define MASK %s\n" % mask)
        outfile.write("#define XADD %d\n\n" % atomic)
        copyfile(src_dir + "0_start.c", outfile)

        for src_block in filenames:
            copyfile(src_dir + src_block, outfile)
        copyfile(src_dir + "c_end.c", outfile)

for atomic in range(0, 2):
    for mask in masklist:
        for blocknum in range(0, 6):
            for memlookups in range(1, 6):
                    if atomic is 1:
                        endname = "_atomic"
                    else:
                        endname = ""
                    filename = "%s_mask_%d_optionals_%d_lookups%s.c" \
                                % (mask, blocknum, memlookups, endname)
                    createfiles(mask, blocknum, memlookups, atomic, filename)
