/*
 * Copyright (c) 2014-2020 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// C standard headers
#include <stdio.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

// C++ standard headers
#include <vector>

// This file is a C++ header file


#define SG_SGL_MAX_ELEMENTS 16384

#define SG_COUNT_INDEFINITE (-1)
#define SG_LBA_INVALID SG_COUNT_INDEFINITE

// Sizing matches largest SCSI READ and WRITE commands plus those of Unix
// read(2)s and write(2)s. User can give larger than 31 bit 'num's but they
// are split into several consecutive elements.
class scat_gath_elem {
public:
    uint64_t lba;       // of start block
    uint32_t num;       // number of blocks from and including start block

    void make_bad() { lba = UINT64_MAX; num = UINT32_MAX; }
    bool is_bad() const { return (lba == UINT64_MAX && num == UINT32_MAX); }
};

// Consider "linearity" as a scatter gather list property. Elements of this
// of from the strongest form to the weakest.
enum sgl_linearity_e {
    SGL_LINEAR = 0,     // empty list and 0,0 considered linear
    SGL_MONOTONIC,      // since not linear, implies holes
    SGL_MONO_OVERLAP,   // monotonic but same LBA in two or more elements
    SGL_NON_MONOTONIC   // weakest
};


// Holds one scatter gather list and its associated metadata
class scat_gath_list {
public:
    scat_gath_list() : linearity(SGL_LINEAR), sum_hard(false), m_errno(0),
        high_lba_p1(0), lowest_lba(0), sum(0) { }

    scat_gath_list(const scat_gath_list &) = default;
    scat_gath_list & operator=(const scat_gath_list &) = default;
    ~scat_gath_list() = default;

    bool empty() const;
    bool empty_or_00() const;
    int num_elems() const;
    int64_t get_lowest_lba(bool ignore_degen, bool always_last) const;
    int64_t get_low_lba_from_linear() const;
    bool is_pipe_suitable() const;

    friend bool sgls_eq_off(const scat_gath_list &left, int l_e_ind,
                            int l_blk_off,
                            const scat_gath_list &right, int r_e_ind,
                            int r_blk_off, bool allow_partial);

    bool load_from_cli(const char * cl_p, bool b_vb);
    bool load_from_file(const char * file_name, bool def_hex, bool flexible,
                        bool b_vb);
    int append_1or(int64_t extra_blks, int64_t start_lba);
    int append_1or(int64_t extra_blks);

    void dbg_print(bool skip_meta, const char * id_str, bool to_stdout,
                   bool show_sgl) const;

    // calculates and sets following bool-s and int64_t-s
    void sum_scan(const char * id_str, bool show_sgl, bool b_verbose);

    void set_weaker_linearity(enum sgl_linearity_e lin);
    enum sgl_linearity_e linearity;
    const char * linearity_as_str() const;

    bool sum_hard;      // 'num' in last element of 'sgl' is > 0
    int m_errno;        // OS failure errno
    int64_t high_lba_p1;  // highest LBA plus 1, next write from and above
    int64_t lowest_lba; // initialized to 0
    int64_t sum;        // of all 'num' elements in 'sgl'

    friend int diff_between_iters(const class scat_gath_iter & left,
                                  const class scat_gath_iter & right);

private:
    friend class scat_gath_iter;

    bool file2sgl_helper(FILE * fp, const char * fnp, bool def_hex,
                         bool flexible, bool b_vb);

    std::vector<scat_gath_elem> sgl;  // an array on heap [0..num_elems())
};


class scat_gath_iter {
public:
    scat_gath_iter(const scat_gath_list & my_scat_gath_list);
    scat_gath_iter(const scat_gath_iter & src) = default;
    scat_gath_iter&  operator=(const scat_gath_iter&) = delete;
    ~scat_gath_iter() = default;

    int64_t current_lba() const;
    int64_t current_lba_rem_num(int & rem_num) const;
    class scat_gath_elem current_elem() const;
    bool at_end() const;
    bool is_sgl_linear() const; // the whole list
    // Should return 1 or more unless max_n<=0 or at_end()
    int linear_for_n_blks(int max_n) const;

    bool set_by_blk_idx(int64_t _blk_idx);
    // add/sub blocks return true if they reach EOL/start, else false
    bool add_blks(uint64_t blk_count);
    bool sub_blks(uint64_t blk_count);

    void dbg_print(const char * id_str, bool to_stdout, int verbose) const;

    friend int diff_between_iters(const class scat_gath_iter & left,
                                  const class scat_gath_iter & right);

    friend bool sgls_eq_from_iters(const class scat_gath_iter & left,
                                   const class scat_gath_iter & right,
                                   bool allow_partial);

private:
    const scat_gath_list &sglist;

    // dual representation: either it_el_ind,it_blk_off or blk_idx
    int it_el_ind;      // refers to sge==sglist[it_el_ind]
    int it_blk_off;     // refers to LBA==(sge.lba + it_blk_off)
    int64_t blk_idx;    // in range: [0 .. sglist.sum)
    bool extend_last;
};
