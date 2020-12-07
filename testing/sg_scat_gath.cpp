/*
 * Copyright (c) 2014-2020 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Version 1.02 [20201124]
 */

// C headers
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

// C++ headers
#include <array>

#include "sg_scat_gath.h"
#include "sg_lib.h"
#include "sg_pr2serr.h"

using namespace std;

#define MAX_SGL_NUM_VAL (INT32_MAX - 1)  /* should reduce for testing */
// #define MAX_SGL_NUM_VAL 7  /* should reduce for testing */
#if MAX_SGL_NUM_VAL > INT32_MAX
#error "MAX_SGL_NUM_VAL cannot exceed 2^31 - 1"
#endif

bool
scat_gath_list::empty() const
{
    return sgl.empty();
}

bool
scat_gath_list::empty_or_00() const
{
    if (sgl.empty())
        return true;
    return ((sgl.size() == 1) && (sgl[0].lba == 0) && (sgl[0].num == 0));
}

int
scat_gath_list::num_elems() const
{
    return sgl.size();
}


/* Read numbers (up to 64 bits in size) from command line (comma (or
 * (single) space **) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. Assumed to be LBA (64 bit) and
 * number_of_block (32 bit) pairs. ** Space on command line needs to
 * be escaped, otherwise it is an operand/option separator. */
bool
scat_gath_list::load_from_cli(const char * cl_p, bool b_vb)
{
    bool split, full_pair;
    int in_len, k, j;
    const int max_nbs = MAX_SGL_NUM_VAL;
    int64_t ll, large_num;
    uint64_t prev_lba;
    char * cp;
    char * c2p;
    const char * lcp;
    class scat_gath_elem sge;

    if (NULL == cl_p) {
        pr2serr("%s: bad arguments\n", __func__);
        goto err_out;
    }
    lcp = cl_p;
    in_len = strlen(cl_p);
    if ('-' == cl_p[0]) {        /* read from stdin */
        pr2serr("%s: logic error: no stdin here\n", __func__);
        goto err_out;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(cl_p, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            if (b_vb)
                pr2serr("%s: error at pos %d\n", __func__, k + 1);
            goto err_out;
        }
        j = 0;
        full_pair = true;
        for (k = 0, split = false; ; ++k) {
            if (split) {
                /* splitting given elem with large number_of_blocks into
                 * multiple elems within array being built */
                ++j;
                sge.lba = prev_lba + (uint64_t)max_nbs;
                if (large_num > max_nbs) {
                    sge.num = (uint32_t)max_nbs;
                    prev_lba = sge.lba;
                    large_num -= max_nbs;
                    sgl.push_back(sge);
                } else {
                    sge.num = (uint32_t)large_num;
                    split = false;
                    if (b_vb)
                        pr2serr("%s: split large sg elem into %d element%s\n",
                                __func__, j, (j == 1 ? "" : "s"));
                    sgl.push_back(sge);
                    goto check_for_next;
                }
                continue;
            }
            full_pair = false;
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                sge.lba = (uint64_t)ll;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp) {
                    cp = c2p;
                    if (NULL == cp)
                        break;
                }
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                if (b_vb)
                    pr2serr("%s: error at pos %d\n", __func__,
                            (int)(lcp - cl_p + 1));
                goto err_out;
            }
            ll = sg_get_llnum(lcp);
            if (ll >= 0) {
                full_pair = true;
                if (ll > max_nbs) {
                    sge.num = (uint32_t)max_nbs;
                    prev_lba = sge.lba;
                    large_num = ll - max_nbs;
                    split = true;
                    j = 1;
                    continue;
                }
                sge.num = (uint32_t)ll;
            } else {    /* bad or negative number as number_of_blocks */
                if (b_vb)
                    pr2serr("%s: bad number at pos %d\n", __func__,
                            (int)(lcp - cl_p + 1));
                goto err_out;
            }
            sgl.push_back(sge);
check_for_next:
            cp = (char *)strchr(lcp, ',');
            c2p = (char *)strchr(lcp, ' ');
            if (NULL == cp) {
                cp = c2p;
                if (NULL == cp)
                    break;
            }
            if (c2p && (c2p < cp))
                cp = c2p;
            lcp = cp + 1;
        }       /* end of for loop over items in operand */
        /* other than first pair, expect even number of items */
        if ((k > 0) && (! full_pair)) {
            if (b_vb)
                pr2serr("%s:  expected even number of items: "
                        "LBA0,NUM0,LBA1,NUM1...\n", __func__);
            goto err_out;
        }
    }
    return true;
err_out:
    if (0 == m_errno)
        m_errno = SG_LIB_SYNTAX_ERROR;
    return false;
}

bool
scat_gath_list::file2sgl_helper(FILE * fp, const char * fnp, bool def_hex,
                                bool flexible, bool b_vb)
{
    bool bit0;
    bool pre_addr1 = true;
    bool pre_hex_seen = false;
    int in_len, k, j, m, ind;
    const int max_nbs = MAX_SGL_NUM_VAL;
    int off = 0;
    int64_t ll;
    uint64_t ull, prev_lba;
    char * lcp;
    class scat_gath_elem sge;
    char line[1024];

    for (j = 0 ; ; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        // could improve with carry_over logic if sizeof(line) too small
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
            } else {
                m_errno = SG_LIB_SYNTAX_ERROR;
                if (b_vb)
                    pr2serr("%s: %s: line too long, max %d bytes\n",
                            __func__, fnp, (int)(sizeof(line) - 1));
                goto err_out;
            }
        }
        if (in_len < 1)
            continue;
        lcp = line;
        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        if (pre_addr1 || pre_hex_seen) {
            /* Accept lines with leading 'HEX' and ignore as long as there
             * is one _before_ any LBA,NUM lines in the file. This allows
             * HEX marked sgls to be concaternated together. */
            if (('H' == toupper(lcp[0])) && ('E' == toupper(lcp[1])) &&
                ('X' == toupper(lcp[2]))) {
                pre_hex_seen = true;
                if (def_hex)
                    continue; /* bypass 'HEX' marker line if expecting hex */
                else {
                    if (flexible) {
                        def_hex = true; /* okay, switch to hex parse */
                        continue;
                    } else {
                        pr2serr("%s: %s: 'hex' string detected on line %d, "
                                "expecting decimal\n", __func__, fnp, j + 1);
                        m_errno = EINVAL;
                        goto err_out;
                    }
                }
            }
        }
        k = strspn(lcp, "0123456789aAbBcCdDeEfFhHxXbBdDiIkKmMgGtTpP, \t");
        if ((k < in_len) && ('#' != lcp[k])) {
            m_errno = EINVAL;
            if (b_vb)
                pr2serr("%s: %s: syntax error at line %d, pos %d\n",
                        __func__, fnp, j + 1, m + k + 1);
            goto err_out;
        }
        for (k = 0; k < 256; ++k) {
            /* limit parseable items on one line to 256 */
            if (def_hex) {      /* don't accept negatives or multipliers */
                if (1 == sscanf(lcp, "%" SCNx64, &ull))
                    ll = (int64_t)ull;
                else
                    ll = -1;    /* use (2**64 - 1) as error flag */
            } else
                ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                ind = ((off + k) >> 1);
                bit0 = !! (0x1 & (off + k));
                if (ind >= SG_SGL_MAX_ELEMENTS) {
                    m_errno = EINVAL;
                    if (b_vb)
                        pr2serr("%s: %s: array length exceeded\n", __func__,
                                fnp);
                    goto err_out;
                }
                if (bit0) {     /* bit0 set when decoding a NUM */
                    if (ll < 0) {
                        m_errno = EINVAL;
                        if (b_vb)
                            pr2serr("%s: %s: bad number in line %d, at pos "
                                    "%d\n", __func__, fnp, j + 1,
                                    (int)(lcp - line + 1));
                        goto err_out;
                    }
                    if (ll > max_nbs) {
                        int h = 1;

                        /* split up this elem into multiple, smaller elems */
                        do {
                            sge.num = (uint32_t)max_nbs;
                            prev_lba = sge.lba;
                            sgl.push_back(sge);
                            sge.lba = prev_lba + (uint64_t)max_nbs;
                            ++h;
                            off += 2;
                            ll -= max_nbs;
                        } while (ll > max_nbs);
                        if (b_vb)
                            pr2serr("%s: split large sg elem into %d "
                                    "elements\n", __func__, h);
                    }
                    sge.num = (uint32_t)ll;
                    sgl.push_back(sge);
                } else {        /* bit0 clear when decoding a LBA */
                    if (pre_addr1)
                        pre_addr1 = false;
                    sge.lba = (uint64_t)ll;
                }
            } else {    /* failed to decode number on line */
                if ('#' == *lcp) { /* numbers before #, rest of line comment */
                    --k;
                    break;      /* goes to next line */
                }
                m_errno = EINVAL;
                if (b_vb)
                    pr2serr("%s: %s: error in line %d, at pos %d\n",
                            __func__, fnp, j + 1, (int)(lcp - line + 1));
                goto err_out;
            }
            lcp = strpbrk(lcp, " ,\t#");
            if ((NULL == lcp) || ('#' == *lcp))
                break;
            lcp += strspn(lcp, " ,\t");
            if ('\0' == *lcp)
                break;
        }       /* <<< end of for(k < 256) loop */
        off += (k + 1);
    }   /* <<< end of for loop, one iteration per line */
    /* allow one items, but not higher odd number of items */
    if ((off > 1) && (0x1 & off)) {
        m_errno = EINVAL;
        if (b_vb)
            pr2serr("%s: %s: expect even number of items: "
                    "LBA0,NUM0,LBA1,NUM1...\n", __func__, fnp);
        goto err_out;
    }
    clearerr(fp);    /* even EOF on first pass needs this before rescan */
    return true;
err_out:
    clearerr(fp);
    return false;
}

/* Read numbers from filename (or stdin), line by line (comma (or (single)
 * space) separated list); places starting_LBA,number_of_block pairs in an
 * array of scat_gath_elem elements pointed to by the returned value. If
 * this fails NULL is returned and an error number is written to errp (if it
 * is non-NULL). Assumed decimal (and may have suffix multipliers) when
 * def_hex==false; if a number is prefixed by '0x', '0X' or contains trailing
 * 'h' or 'H' that denotes a hex number. When def_hex==true all numbers are
 * assumed to be hex (ignored '0x' prefixes and 'h' suffixes) and multiplers
 * are not permitted. Heap allocates an array just big enough to hold all
 * elements if the file is countable. Pipes and stdin are not considered
 * countable. In the non-countable case an array of MAX_FIXED_SGL_ELEMS
 * elements is pre-allocated; if it is exceeded sg_convert_errno(EDOM) is
 * placed in *errp (if it is non-NULL). One of the first actions is to write
 * 0 to *errp (if it is non-NULL) so the caller does not need to zero it
 * before calling. */
bool
scat_gath_list::load_from_file(const char * file_name, bool def_hex,
                               bool flexible, bool b_vb)
{
    bool have_stdin;
    bool have_err = false;
    FILE * fp;
    const char * fnp;

    have_stdin = ((1 == strlen(file_name)) && ('-' == file_name[0]));
    if (have_stdin) {
        fp = stdin;
        fnp = "<stdin>";
    } else {
        fnp = file_name;
        fp = fopen(fnp, "r");
        if (NULL == fp) {
            m_errno = errno;
            if (b_vb)
                pr2serr("%s: opening %s: %s\n", __func__, fnp,
                        safe_strerror(m_errno));
            return false;
        }
    }
    if (! file2sgl_helper(fp, fnp, def_hex, flexible, b_vb))
        have_err = true;
    if (! have_stdin)
        fclose(fp);
    return have_err ? false : true;
}

const char *
scat_gath_list::linearity_as_str() const
{
    switch (linearity) {
    case SGL_LINEAR:
        return "linear";
    case SGL_MONOTONIC:
        return "monotonic";
    case SGL_MONO_OVERLAP:
        return "monotonic, overlapping";
    case SGL_NON_MONOTONIC:
        return "non-monotonic";
    default:
        return "unknown";
    }
}

void
scat_gath_list::set_weaker_linearity(enum sgl_linearity_e lin)
{
    int i_lin = (int)lin;

    if (i_lin > (int)linearity)
        linearity = lin;
}

/* id_str may be NULL (if so replace by "unknown"), present to enhance verbose
 * output. */
void
scat_gath_list::dbg_print(bool skip_meta, const char * id_str, bool to_stdout,
                          bool show_sgl) const
{
    int k;
    int num = sgl.size();
    const char * caller = id_str ? id_str : "unknown";
    FILE * fp = to_stdout ? stdout : stderr;

    if (! skip_meta) {
        fprintf(fp, "%s: elems=%d, sgl %spresent, linearity=%s\n",
                caller, num, (sgl.empty() ? "not " : ""),
                linearity_as_str());
        fprintf(fp, "  sum=%" PRId64 ", sum_hard=%s lowest=0x%" PRIx64
                ", high_lba_p1=", sum, (sum_hard ? "true" : "false"),
                lowest_lba);
        fprintf(fp, "0x%" PRIx64 "\n", high_lba_p1);
    }
    fprintf(fp, "  >> %s scatter gather list (%d element%s):\n", caller, num,
            (num == 1 ? "" : "s"));
    if (show_sgl) {
        for (k = 0; k < num; ++k) {
            const class scat_gath_elem & sge = sgl[k];

            fprintf(fp, "    lba: 0x%" PRIx64 ", number: 0x%" PRIx32,
                    sge.lba, sge.num);
            if (sge.lba > 0)
                fprintf(fp, " [next lba: 0x%" PRIx64 "]", sge.lba + sge.num);
            fprintf(fp, "\n");
        }
    }
}

/* Assumes sgl array (vector) is setup. The other fields in this object are
 * set by analyzing sgl in a single pass. The fields that are set are:
 * fragmented, lowest_lba, high_lba_p1, monotonic, overlapping, sum and
 * sum_hard. Degenerate elements (i.e. those with 0 blocks) are ignored apart
 * from when one is last which makes sum_hard false and its LBA becomes
 * high_lba_p1 if it is the highest in the list. An empty sgl is equivalent
 * to a 1 element list with [0, 0], so sum_hard==false, monit==true,
 * fragmented==false and overlapping==false . id_str may be NULL, present
 * to enhance verbose output. */
void
scat_gath_list::sum_scan(const char * id_str, bool show_sgl, bool b_vb)
{
    bool degen = false;
    bool first = true;
    bool regular = true;        /* no overlapping segments detected */
    int k;
    int elems = sgl.size();
    uint32_t prev_num, t_num;
    uint64_t prev_lba, t_lba, low, high, end;

    sum = 0;
    for (k = 0, low = 0, high = 0; k < elems; ++k) {
        const class scat_gath_elem & sge = sgl[k];

        degen = false;
        t_num = sge.num;
        if (0 == t_num) {
            degen = true;
            if (! first)
                continue;       /* ignore degen element that not first */
        }
        if (first) {
            low = sge.lba;
            sum = t_num;
            high = sge.lba + sge.num;
            first = false;
        } else {
            t_lba = sge.lba;
            if ((prev_lba + prev_num) != t_lba)
                set_weaker_linearity(SGL_MONOTONIC);
            sum += t_num;
            end = t_lba + t_num;
            if (end > high)
                high = end;     /* high is one plus highest LBA */
            if (prev_lba < t_lba)
                ;
            else if (prev_lba == t_lba) {
                if (prev_num > 0) {
                    set_weaker_linearity(SGL_MONO_OVERLAP);
                    break;
                }
            } else {
                low = t_lba;
                set_weaker_linearity(SGL_NON_MONOTONIC);
                break;
            }
            if (regular) {
                if ((prev_lba + prev_num) > t_lba)
                    regular = false;
            }
        }
        prev_lba = sge.lba;
        prev_num = sge.num;
    }           /* end of for loop while still elements and monot true */

    if (k < elems) {    /* only here if above breaks are taken */
        prev_lba = t_lba;
        ++k;
        for ( ; k < elems; ++k) {
            const class scat_gath_elem & sge = sgl[k];

            degen = false;
            t_lba = sge.lba;
            t_num = sge.num;
            if (0 == t_num) {
                degen = true;
                continue;
            }
            sum += t_num;
            end = t_lba + t_num;
            if (end > high)
                high = end;
            if (prev_lba > t_lba) {
                if (t_lba < low)
                    low = t_lba;
            }
            prev_lba = t_lba;
        }
    } else
        if (! regular)
            set_weaker_linearity(SGL_MONO_OVERLAP);

    lowest_lba = low;
    if (degen && (elems > 0)) { /* last element always impacts high_lba_p1 */
        t_lba = sgl[elems - 1].lba;
        high_lba_p1 = (t_lba > high) ? t_lba : high;
    } else
        high_lba_p1 = high;
    sum_hard = (elems > 0) ? ! degen : false;
    if (b_vb)
        dbg_print(false, id_str, false, show_sgl);
}

/* Usually will append (or add to start if empty) sge unless 'extra_blks'
 * exceeds MAX_SGL_NUM_VAL. In that case multiple sge_s are added with
 * sge.num = MAX_SGL_NUM_VAL or less (for final sge) until extra_blks is
 * exhausted. Returns new size of scatter gather list. */
int
scat_gath_list::append_1or(int64_t extra_blks, int64_t start_lba)
{
    int o_num = sgl.size();
    const int max_nbs = MAX_SGL_NUM_VAL;
    int64_t cnt = 0;
    class scat_gath_elem sge;

    if ((extra_blks <= 0) && (start_lba < 0))
        return o_num;       /* nothing to do */
    if ((o_num > 0) && (! sum_hard)) {
        sge = sgl[o_num - 1];   /* assume sge.num==0 */
        if (sge.lba == (uint64_t)start_lba) {
            if (extra_blks <= max_nbs)
                sge.num = extra_blks;
            else
                sge.num = max_nbs;
            sgl[o_num - 1] = sge;
            cnt = sge.num;
            sum += cnt;
            sum_hard = true;
            if (cnt <= extra_blks) {
                high_lba_p1 = sge.lba + cnt;
                return o_num;
            }
        }
    } else if (0 == o_num) {
        lowest_lba = start_lba;
        if (0 == extra_blks) {
            sge.lba = start_lba;
            sge.num = 0;
            sgl.push_back(sge);
            high_lba_p1 = sge.lba;
            return sgl.size();
        }
    }
    for ( ; cnt < extra_blks; cnt += max_nbs) {
        sge.lba = start_lba + cnt;
        if ((extra_blks - cnt) <= max_nbs)
            sge.num = extra_blks - cnt;
        else
            sge.num = max_nbs;
        sgl.push_back(sge);
        sum += sge.num;
    }           /* always loops at least once */
    sum_hard = true;
    high_lba_p1 = sge.lba + sge.num;
    return sgl.size();
}

int
scat_gath_list::append_1or(int64_t extra_blks)
{
    int o_num = sgl.size();

    if (o_num < 1)
        return append_1or(extra_blks, 0);

    class scat_gath_elem sge = sgl[o_num - 1];

    return append_1or(extra_blks, sge.lba + sge.num);
}

bool
sgls_eq_off(const scat_gath_list & left, int l_e_ind, int l_blk_off,
            const scat_gath_list & right, int r_e_ind, int r_blk_off,
            bool allow_partial)
{
    int lrem, rrem;
    int lelems = left.sgl.size();
    int relems = right.sgl.size();

    while ((l_e_ind < lelems) && (r_e_ind < relems)) {
        if ((left.sgl[l_e_ind].lba + l_blk_off) !=
            (right.sgl[r_e_ind].lba + r_blk_off))
            return false;
        lrem = left.sgl[l_e_ind].num - l_blk_off;
        rrem = right.sgl[r_e_ind].num - r_blk_off;
        if (lrem == rrem) {
            ++l_e_ind;
            l_blk_off = 0;
            ++r_e_ind;
            r_blk_off = 0;
        } else if (lrem < rrem) {
            ++l_e_ind;
            l_blk_off = 0;
            r_blk_off += lrem;
        } else {
            ++r_e_ind;
            r_blk_off = 0;
            l_blk_off += rrem;
        }
    }
    if ((l_e_ind >= lelems) && (r_e_ind >= relems))
        return true;
    return allow_partial;
}

/* If bad arguments returns -1, otherwise returns the lowest LBA in *sglp .
 * If no elements considered returns 0. If ignore_degen is true than
 * ignores all elements with sge.num zero unless always_last is also
 * true in which case the last element is always considered. */
int64_t
scat_gath_list::get_lowest_lba(bool ignore_degen, bool always_last) const
{
    int k;
    const int num_elems = sgl.size();
    bool some = (num_elems > 0);
    int64_t res = INT64_MAX;

    for (k = 0; k < num_elems; ++k) {
        if ((0 == sgl[k].num) && ignore_degen)
            continue;
        if ((int64_t)sgl[k].lba < res)
            res = sgl[k].lba;
    }
    if (always_last && some) {
        if ((int64_t)sgl[k - 1].lba < res)
            res = sgl[k - 1].lba;
    }
    return (INT64_MAX == res) ? 0 : res;
}

/* Returns >= 0 if sgl can be simplified to a single LBA. So an empty sgl
 * will return 0; a one element sgl will return its LBA. A multiple element
 * sgl only returns the first element's LBA (that is not degenerate) if the
 * sgl is monotonic and not fragmented. In the extreme case takes last
 * element's LBA if all prior elements are degenerate. Else returns -1 .
 * Assumes sgl_sum_scan() has been called. */
int64_t
scat_gath_list::get_low_lba_from_linear() const
{
    const int num_elems = sgl.size();
    int k;

    if (num_elems <= 1)
        return (1 == num_elems) ? sgl[0].lba : 0;
    else {
        if (linearity == SGL_LINEAR) {
            for (k = 0; k < (num_elems - 1); ++k) {
                if (sgl[k].num > 0)
                    return sgl[k].lba;
            }
            /* take last element's LBA if all earlier are degenerate */
            return sgl[k].lba;
        } else
            return -1;
    }
}

bool
scat_gath_list::is_pipe_suitable() const
{
    return (lowest_lba == 0) && (linearity == SGL_LINEAR);
}

scat_gath_iter::scat_gath_iter(const scat_gath_list & parent)
    : sglist(parent), it_el_ind(0), it_blk_off(0), blk_idx(0)
{
    int elems = sglist.num_elems();

    if (elems > 0)
        extend_last = (0 == sglist.sgl[elems - 1].num);
}

bool
scat_gath_iter::set_by_blk_idx(int64_t _blk_idx)
{
    bool first;
    int k;
    const int elems = sglist.sgl.size();
    const int last_ind = elems - 1;
    uint32_t num;
    int64_t bc = _blk_idx;

    if (bc < 0)
        return false;

    if (bc == blk_idx)
        return true;
    else if (bc > blk_idx) {
        k = it_el_ind;
        bc -= blk_idx;
    } else
        k = 0;
    for (first = true; k < elems; ++k, first = false) {
        num = ((k == last_ind) && extend_last) ? MAX_SGL_NUM_VAL :
                                                 sglist.sgl[k].num;
        if (first) {
            if ((int64_t)(num - it_blk_off) < bc)
                bc -= (num - it_blk_off);
            else {
                it_blk_off = bc + it_blk_off;
                break;
            }
        } else {
            if ((int64_t)num < bc)
                bc -= num;
            else {
                it_blk_off = (uint32_t)bc;
                break;
            }
        }
    }
    it_el_ind = k;
    blk_idx = _blk_idx;

    if (k < elems)
        return true;
    else if ((k == elems) && (0 == it_blk_off))
        return true;    /* EOL */
    else
        return false;
}

/* Given a blk_count, the iterator (*iter_p) is moved toward the EOL.
 * Returns true unless blk_count takes iterator two or more past the last
 * element. So if blk_count takes the iterator to the EOL, this function
 * returns true. Takes into account iterator's extend_last flag. */
bool
scat_gath_iter::add_blks(uint64_t blk_count)
{
    bool first;
    int k;
    const int elems = sglist.sgl.size();
    const int last_ind = elems - 1;
    uint32_t num;
    uint64_t bc = blk_count;

    if (0 == bc)
        return true;
    for (first = true, k = it_el_ind; k < elems; ++k) {
        num = ((k == last_ind) && extend_last) ? MAX_SGL_NUM_VAL :
                                                 sglist.sgl[k].num;
        if (first) {
            first = false;
            if ((uint64_t)(num - it_blk_off) <= bc)
                bc -= (num - it_blk_off);
            else {
                it_blk_off = bc + it_blk_off;
                break;
            }
        } else {
            if ((uint64_t)num <= bc)
                bc -= num;
            else {
                it_blk_off = (uint32_t)bc;
                break;
            }
        }
    }
    it_el_ind = k;
    blk_idx += blk_count;

    if (k < elems)
        return true;
    else if ((k == elems) && (0 == it_blk_off))
        return true;    /* EOL */
    else
        return false;
}

/* Move the iterator from its current position (which may be to EOL) towards
 * the start of the sgl (i.e. backwards) for blk_count blocks. Returns true
 * if iterator is valid after the move, else returns false. N.B. if false is
 * returned, then the iterator is invalid and may need to set it to a valid
 * value. */
bool
scat_gath_iter::sub_blks(uint64_t blk_count)
{
    bool first;
    int k = it_el_ind;
    uint64_t bc = 0;
    const uint64_t orig_blk_count = blk_count;

    if (0 == blk_count)
        return true;
    for (first = true; k >= 0; --k) {
        if (first) {
            if (blk_count > (uint64_t)it_blk_off)
                blk_count -= it_blk_off;
            else {
                it_blk_off -= blk_count;
                break;
            }
            first = false;
        } else {
            uint32_t off = sglist.sgl[k].num;

            bc = blk_count;
            if (bc > (uint64_t)off)
                blk_count -= off;
            else {
                bc = off - bc;
                break;
            }
        }
    }
    if (k < 0) {
        blk_idx = 0;
        it_blk_off = 0;
        return false;           /* bad situation */
    }
    if ((int64_t)orig_blk_count <= blk_idx)
        blk_idx -= orig_blk_count;
    else
        blk_idx = 0;
    it_el_ind = k;
    if (! first)
        it_blk_off = (uint32_t)bc;
    return true;
}

/* Returns LBA referred to by iterator if valid or returns SG_LBA_INVALID
 * (-1) if at end or invalid. */
int64_t
scat_gath_iter::current_lba() const
{
    const int elems = sglist.sgl.size();
    int64_t res = SG_LBA_INVALID; /* for at end or invalid (-1) */

    if (it_el_ind < elems) {
        class scat_gath_elem sge = sglist.sgl[it_el_ind];

        if ((uint32_t)it_blk_off < sge.num)
            return sge.lba + it_blk_off;
        else if (((uint32_t)it_blk_off == sge.num) &&
                 ((it_el_ind + 1) < elems)) {
            class scat_gath_iter iter(*this);

            ++iter.it_el_ind;
            iter.it_blk_off = 0;
            /* worst case recursion will stop at end of sgl */
            return iter.current_lba();
        }
    }
    return res;
}

int64_t
scat_gath_iter::current_lba_rem_num(int & rem_num) const
{
    const int elems = sglist.sgl.size();
    int64_t res = SG_LBA_INVALID; /* for at end or invalid (-1) */

    if (it_el_ind < elems) {
        class scat_gath_elem sge = sglist.sgl[it_el_ind];

        if ((uint32_t)it_blk_off < sge.num) {
            rem_num = sge.num - it_blk_off;
            return sge.lba + it_blk_off;
        } else if (((uint32_t)it_blk_off == sge.num) &&
                 ((it_el_ind + 1) < elems)) {
            class scat_gath_iter iter(*this);

            ++iter.it_el_ind;
            iter.it_blk_off = 0;
            /* worst case recursion will stop at end of sgl */
            return iter.current_lba_rem_num(rem_num);
        }
    }
    rem_num = -1;
    return res;
}

class scat_gath_elem
scat_gath_iter::current_elem() const
{
    const int elems = sglist.sgl.size();
    class scat_gath_elem sge;

    sge.make_bad();
    if (it_el_ind < elems)
        return sglist.sgl[it_el_ind];
    return sge;
}

/* Returns true of no sgl or sgl is at the end [elems, 0], otherwise it
 * returns false. */
bool
scat_gath_iter::at_end() const
{
    const int elems = sglist.sgl.size();

    return ((0 == elems) || ((it_el_ind == elems) && (0 == it_blk_off)));
}

/* Returns true if associated iterator is monotonic (increasing) and not
 * fragmented. Empty sgl and single element degenerate considered linear.
 * Assumes sgl_sum_scan() has been called on sgl. */
bool
scat_gath_iter::is_sgl_linear() const
{
    return sglist.linearity == SGL_LINEAR;
}

/* Should return 1 or more unless max_n<=0 or at_end() */
int
scat_gath_iter::linear_for_n_blks(int max_n) const
{
    int k, rem;
    const int elems = sglist.sgl.size();
    uint64_t prev_lba;
    class scat_gath_elem sge;

    if (at_end() || (max_n <= 0))
        return 0;
    sge = sglist.sgl[it_el_ind];
    rem = (int)sge.num - it_blk_off;
    if (rem <= 0) {
        sge = sglist.sgl[it_el_ind + 1];
        rem = (int)sge.num;
    }
    if (max_n <= rem)
        return max_n;
    prev_lba = sge.lba + sge.num;
    for (k = it_el_ind + 1; k < elems; ++k) {
        sge = sglist.sgl[k];
        if (sge.lba != prev_lba)
            return rem;
        rem += sge.num;
        if (max_n <= rem)
            return max_n;
        prev_lba = sge.lba + sge.num;
    }
    return rem;
}

/* id_str may be NULL (if so replace by "unknown"), present to enhance verbose
 * output. */
void
scat_gath_iter::dbg_print(const char * id_str, bool to_stdout,
                          int verbose) const
{
    const char * caller = id_str ? id_str : "unknown";
    FILE * fp = to_stdout ? stdout : stderr;

    fprintf(fp, "%s: it_el_ind=%d, it_blk_off=%d, blk_idx=%" PRId64 "\n",
            caller, it_el_ind, it_blk_off, blk_idx);
    fprintf(fp, "  extend_last=%d\n", extend_last);
    if (verbose)
        sglist.dbg_print(false, " iterator's", to_stdout, verbose > 1);
}

/* Calculates difference between iterators, logically: res <-- lhs - rhs
 * Checks that lhsp and rhsp have same underlying sgl, if not returns
 * INT_MIN. Assumes iterators close enough for result to lie in range
 * from (-INT_MAX) to INT_MAX (inclusive). */
int
diff_between_iters(const class scat_gath_iter & left,
                   const class scat_gath_iter & right)
{
    int res, k, r_e_ind, l_e_ind;

    if (&left.sglist != &right.sglist) {
        pr2serr("%s: bad args\n", __func__);
        return INT_MIN;
    }
    r_e_ind = right.it_el_ind;
    l_e_ind = left.it_el_ind;
    if (l_e_ind < r_e_ind) { /* so difference will be negative */
        res = diff_between_iters(right, left);        /* cheat */
        if (INT_MIN == res)
            return res;
        return -res;
    } else if (l_e_ind == r_e_ind)
        return (int)left.it_blk_off - (int)right.it_blk_off;
    /* (l_e_ind > r_e_ind) so (lhs > rhs) */
    res = (int)right.sglist.sgl[r_e_ind].num - right.it_blk_off;
    for (k = 1; (r_e_ind + k) < l_e_ind; ++k) {
        // pr2serr("%s: k=%d, res=%d, num=%d\n", __func__, k, res,
        //         (int)right.sglist.sgl[r_e_ind + k].num);
        res += (int)right.sglist.sgl[r_e_ind + k].num;
    }
    res += left.it_blk_off;
    // pr2serr("%s: at exit res=%d\n", __func__, res);
    return res;
}

/* Compares from the current iterator positions of left and left until
 * the shorter list is exhausted. Returns false on the first inequality.
 * If no inequality and both remaining lists are same length then returns
 * true. If no inequality but remaining lists differ in length then returns
 * allow_partial. */
bool
sgls_eq_from_iters(const class scat_gath_iter & left,
                   const class scat_gath_iter & right,
                   bool allow_partial)
{
    return sgls_eq_off(left.sglist, left.it_el_ind, left.it_blk_off,
                       right.sglist, right.it_el_ind, right.it_blk_off,
                       allow_partial);
}
