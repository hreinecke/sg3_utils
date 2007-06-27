/*
 * isosize : use iso9660 header info to find size of associated
 *           iso9660 file system
 *
 *  Copyright (C) 2000 Andries Brouwer
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * isosize.c - Andries Brouwer, 000608
 *
 * Synopsis:
 *    isosize [-x] [-d <num>] <filename>
 *        where "-x" gives length in sectors and sector size while
 *              without this argument the size is given in bytes
 *        without "-x" gives length in bytes unless "-d <num>" is
 *		given. In the latter case the length in bytes divided
 *		by <num> is given
 *
 *  Version 2.03 2000/12/21
 *     - add "-d <num>" option and use long long to fix things > 2 GB
 *  Version 2.02 2000/10/11
 *     - error messages on IO failures [D. Gilbert]
 *
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define ISODCL(from, to) (to - from + 1)

int xflag;

int
isonum_721 (unsigned char * p) {
        return ((p[0] & 0xff)
                | ((p[1] & 0xff) << 8));
}

int
isonum_722 (unsigned char * p) {
        return ((p[1] & 0xff)
                | ((p[0] & 0xff) << 8));
}

int
isonum_723 (unsigned char * p) {
        int le = isonum_721 (p);
        int be = isonum_722 (p+2);
        if (xflag && le != be)
                fprintf(stderr, "723error: le=%d be=%d\n", le, be);
        return (le);
}

int
isonum_731 (unsigned char * p) {
    return ((p[0] & 0xff)
            | ((p[1] & 0xff) << 8)
            | ((p[2] & 0xff) << 16)
            | ((p[3] & 0xff) << 24));
}

int
isonum_732 (unsigned char * p) {
    return ((p[3] & 0xff)
            | ((p[2] & 0xff) << 8)
            | ((p[1] & 0xff) << 16)
            | ((p[0] & 0xff) << 24));
}


int
isonum_733 (unsigned char * p) {
    int le = isonum_731 (p);
    int be = isonum_732 (p+4);
    if (xflag && le != be)
            fprintf(stderr, "733error: le=%d be=%d\n", le, be);
    return (le);
}

struct iso_primary_descriptor {
    unsigned char type                      [ISODCL (  1,   1)]; /* 711 */
    unsigned char id                        [ISODCL (  2,   6)];
    unsigned char version                   [ISODCL (  7,   7)]; /* 711 */
    unsigned char unused1                   [ISODCL (  8,   8)];
    unsigned char system_id                 [ISODCL (  9,  40)]; /* auchars */
    unsigned char volume_id                 [ISODCL ( 41,  72)]; /* duchars */
    unsigned char unused2                   [ISODCL ( 73,  80)];
    unsigned char volume_space_size         [ISODCL ( 81,  88)]; /* 733 */
    unsigned char unused3                   [ISODCL ( 89, 120)];
    unsigned char volume_set_size           [ISODCL (121, 124)]; /* 723 */
    unsigned char volume_sequence_number    [ISODCL (125, 128)]; /* 723 */
    unsigned char logical_block_size        [ISODCL (129, 132)]; /* 723 */
    unsigned char path_table_size           [ISODCL (133, 140)]; /* 733 */
    unsigned char type_l_path_table         [ISODCL (141, 144)]; /* 731 */
    unsigned char opt_type_l_path_table     [ISODCL (145, 148)]; /* 731 */
    unsigned char type_m_path_table         [ISODCL (149, 152)]; /* 732 */
    unsigned char opt_type_m_path_table     [ISODCL (153, 156)]; /* 732 */
    unsigned char root_directory_record     [ISODCL (157, 190)]; /* 9.1 */
    unsigned char volume_set_id             [ISODCL (191, 318)]; /* duchars */
    unsigned char publisher_id              [ISODCL (319, 446)]; /* achars */
    unsigned char preparer_id               [ISODCL (447, 574)]; /* achars */
    unsigned char application_id            [ISODCL (575, 702)]; /* achars */
    unsigned char copyright_file_id         [ISODCL (703, 739)]; /* 7.5 dchars */
    unsigned char abstract_file_id          [ISODCL (740, 776)]; /* 7.5 dchars */
    unsigned char bibliographic_file_id     [ISODCL (777, 813)]; /* 7.5 dchars */
    unsigned char creation_date             [ISODCL (814, 830)]; /* 8.4.26.1 */
    unsigned char modification_date         [ISODCL (831, 847)]; /* 8.4.26.1 */
    unsigned char expiration_date           [ISODCL (848, 864)]; /* 8.4.26.1 */
    unsigned char effective_date            [ISODCL (865, 881)]; /* 8.4.26.1 */
    unsigned char file_structure_version    [ISODCL (882, 882)]; /* 711 */
    unsigned char unused4                   [ISODCL (883, 883)];
    unsigned char application_data          [ISODCL (884, 1395)];
    unsigned char unused5                   [ISODCL (1396, 2048)];
};

int main(int argc, char * argv[]) {
    struct iso_primary_descriptor ipd;
    int fd, nsecs, ssize, j, m;
    int divisor = 0;
    const char * filenamep = NULL;

    for (j = 1; j < argc; ++j) {
	if (0 == strncmp("-d", argv[j], 2)) {
	    if (strlen(argv[j]) > 2)
		m = 2;
	    else {
		++j;
		if (j >= argc) {
		    filenamep = NULL;
		    break;
		}
		m = 0;
	    }
	    if (1 != sscanf(argv[j] + m, "%d", &divisor)) {
	    	fprintf(stderr, "Couldn't decode number after '-d' switch\n");
		filenamep = NULL;
		break;
	    }
	}
	else if (0 == strcmp("-x", argv[j]))
	    xflag = 1;
	else if (*argv[j] == '-') {
            fprintf(stderr, "Unrecognized switch: %s\n", argv[j]);
            filenamep = NULL;
            break;
        }
        else
            filenamep = argv[j];
    }

    if(filenamep == NULL) {
        fprintf(stderr, "Usage: isosize [-x] [-d <num>] iso9660-image\n");
        return 1;
    }

    if ((fd = open(filenamep,O_RDONLY)) < 0) {
        fprintf(stderr, "failed to open: %s", filenamep);
        perror(", error");
        return 1;
    }
    if (lseek(fd, 16 << 11, 0) == (off_t)-1) {
        perror("lseek error");
        return 1;
    }
    if (read(fd, &ipd, sizeof(ipd)) < 0) {
        perror("read error");
        return 1;
    }

    nsecs = isonum_733(ipd.volume_space_size);
    ssize = isonum_723(ipd.logical_block_size); /* nowadays always 2048 */

    if (xflag)
        printf ("sector count: %d, sector size: %d\n", nsecs, ssize);
    else {
	long long product = nsecs;

	if (0 == divisor)
	    printf ("%lld\n", product * ssize);
	else if (divisor == ssize)
	    printf ("%d\n", nsecs);
	else
	    printf ("%lld\n", (product * ssize) / divisor);
    }
    return 0;
}
