/* Code fragment of how to get a buffer of heap that has a specific
 * alignment, typically 'page' size which is 4096 bytes. */

    uint8_t * wrkBuff;	/* will get pointer to heap allocation */
    uint8_t * wrkPos;	/* will get aligned pointer within wrkBuff */
    uint32_t sz_of_aligned = 1234;	/* number of aligned bytes required */

    int psz;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    psz = sysconf(_SC_PAGESIZE); /* POSIX.1 (was getpagesize()) */
#else
    psz = 4096;     /* give up, pick likely figure */
#endif


   /* perhaps use posix_memalign() instead. Yes but not always available */
    wrkBuff = (uint8_t *)malloc(sz_of_aligned + psz);
    wrkPos = (uint8_t *)(((sg_uintptr_t)wrkBuff + psz - 1) & (~(psz - 1)));
