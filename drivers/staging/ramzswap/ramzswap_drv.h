/*
 * Compressed RAM based swap device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 * Project home: http://compcache.googlecode.com
 */

#ifndef _RAMZSWAP_DRV_H_
#define _RAMZSWAP_DRV_H_

#include <linux/spinlock.h>
#include <linux/mutex.h>

#include "ramzswap_ioctl.h"
#include "xvmalloc.h"

/*
 * Some arbitrary value. This is just to catch
 * invalid value for num_devices module parameter.
 */
static const unsigned max_num_devices = 32;

/*
 * Stored at beginning of each compressed object.
 *
 * It stores back-reference to table entry which points to this
 * object. This is required to support memory defragmentation.
 */
struct zobj_header {
#if 0
	u32 table_idx;
#endif
};

/*-- Configurable parameters */

/* Default ramzswap disk size: 25% of total RAM */
static const unsigned default_disksize_perc_ram = 25;

/*
 * Pages that compress to size greater than this are stored
 * uncompressed in memory.
 */
static const unsigned max_zpage_size = PAGE_SIZE / 4 * 3;

/*
 * NOTE: max_zpage_size must be less than or equal to:
 *   XV_MAX_ALLOC_SIZE - sizeof(struct zobj_header)
 * otherwise, xv_malloc() would always return failure.
 */

/*-- End of configurable params */

#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)
#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE	(1 << SECTORS_PER_PAGE_SHIFT)

#if defined(CONFIG_ZRAM_LZO) + defined(CONFIG_ZRAM_SNAPPY) == 0
#error At least one of CONFIG_ZRAM_LZO, CONFIG_ZRAM_SNAPPY must be defined!
#endif
#if defined(CONFIG_ZRAM_LZO) + defined(CONFIG_ZRAM_SNAPPY) > 1
#define MULTIPLE_COMPRESSORS
#endif

/* Flags for zram pages (table[page_no].flags) */
enum zram_pageflags {
	/* Page is stored uncompressed */
	RZS_UNCOMPRESSED,

	/* Page consists entirely of zeros */
	RZS_ZERO,

	__NR_RZS_PAGEFLAGS,
};

/*-- Data structures */

/*
 * Allocated for each swap slot, indexed by page no.
 * These table entries must fit exactly in a page.
 */
struct table {
	struct page *page;
	u16 offset;
	u8 count;	/* object ref count (not yet used) */
	u8 flags;
} __attribute__((aligned(4)));

struct ramzswap_stats {
	/* basic stats */
	size_t compr_size;	/* compressed size of pages stored -
				 * needed to enforce memlimit */
	/* more stats */
#if defined(CONFIG_RAMZSWAP_STATS)
	u64 num_reads;		/* failed + successful */
	u64 num_writes;		/* --do-- */
	u64 failed_reads;	/* should NEVER! happen */
	u64 failed_writes;	/* can happen when memory is too low */
	u64 invalid_io;		/* non-swap I/O requests */
	u64 notify_free;	/* no. of swap slot free notifications */
	u64 discard;		/* no. of block discard callbacks */
	u32 pages_zero;		/* no. of zero filled pages */
	u32 pages_stored;	/* no. of pages currently stored */
	u32 good_compress;	/* % of pages with compression ratio<=50% */
	u32 pages_expand;	/* % of incompressible pages */
#endif
};

struct ramzswap {
	struct xv_pool *mem_pool;
#ifdef MULTIPLE_COMPRESSORS
	const struct zram_compressor *compressor;
#endif
	void *compress_workmem;
	void *compress_buffer;
	struct table *table;
	spinlock_t stat64_lock;	/* protect 64-bit stats */
	struct mutex lock;
	struct request_queue *queue;
	struct gendisk *disk;
	int init_done;
	/*
	 * This is limit on amount of *uncompressed* worth of data
	 * we can hold. When backing swap device is provided, it is
	 * set equal to device size.
	 */
	size_t disksize;	/* bytes */

	struct ramzswap_stats stats;
};


extern struct zram *zram_devices;
extern unsigned int num_devices;
#ifdef CONFIG_SYSFS
extern struct attribute_group zram_disk_attr_group;
#endif

extern int zram_init_device(struct zram *zram);
extern void zram_reset_device(struct zram *zram);

#ifdef MULTIPLE_COMPRESSORS
struct zram_compressor {
	const char *name;
	int (*compress)(
		const unsigned char *src,
		size_t src_len,
		unsigned char *dst,
		size_t *dst_len,
		void *workmem);
	int (*decompress)(
		const unsigned char *src,
		size_t src_len,
		unsigned char *dst,
		size_t *dst_len);
	unsigned workmem_bytes;
};

extern const struct zram_compressor * const zram_compressors[];
#endif

#endif
