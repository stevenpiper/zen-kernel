/*
 * Copyright (C) 2008 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <asm/unaligned.h>
#include "lz4.h"
#include "lz4hc.h"
#include "compression.h"

#define LZ4_LEN		4
#define LZ4_CHUNK_SIZE	(4096)
#define LZ4_MAX_WORKBUF	2*LZ4_CHUNK_SIZE

struct workspace {
	void *mem;	/* work memory for compression */
	void *buf;	/* where compressed data goes */
	void *cbuf;	/* where decompressed data goes */
	struct list_head list;
};

static void lz4_free_workspace(struct list_head *ws)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);

	vfree(workspace->buf);
	vfree(workspace->cbuf);
	vfree(workspace->mem);
	kfree(workspace);
}

static struct list_head *lz4_alloc_workspace_generic(int hi)
{
	struct workspace *workspace;

	workspace = kzalloc(sizeof(*workspace), GFP_NOFS);
	if (!workspace)
		return ERR_PTR(-ENOMEM);

	if (hi)
		workspace->mem = vmalloc(LZ4_contextHC_size());
	else
		workspace->mem = vmalloc(LZ4_context64k_size());
	workspace->buf = vmalloc(LZ4_MAX_WORKBUF);
	workspace->cbuf = vmalloc(LZ4_MAX_WORKBUF);
	if (!workspace->mem || !workspace->buf || !workspace->cbuf)
		goto fail;

	INIT_LIST_HEAD(&workspace->list);

	return &workspace->list;
fail:
	lz4_free_workspace(&workspace->list);
	return ERR_PTR(-ENOMEM);
}

static struct list_head *lz4_alloc_workspace(void)
{
	return lz4_alloc_workspace_generic(0);
}

static struct list_head *lz4hc_alloc_workspace(void)
{
	return lz4_alloc_workspace_generic(1);
}

static inline void write_compress_length(char *buf, size_t len)
{
	__le32 dlen;

	dlen = cpu_to_le32(len);
	memcpy(buf, &dlen, LZ4_LEN);
}

static inline size_t read_compress_length(char *buf)
{
	__le32 dlen;

	memcpy(&dlen, buf, LZ4_LEN);
	return le32_to_cpu(dlen);
}
static int lz4_compress_pages_v0(struct list_head *ws,
			      struct address_space *mapping,
			      u64 start, unsigned long len,
			      struct page **pages,
			      unsigned long nr_dest_pages,
			      unsigned long *out_pages,
			      unsigned long *total_in,
			      unsigned long *total_out,
			      unsigned long max_out, int hi);

struct compress_header_v0 {
	__le32 bytes_compressed;
};
struct compress_header_v1 {
	/* 1M length max */
	__le32 comp_len; /* at most 20 bits, 30-31 bits: version */
	__le32 orig_len; /* at most 20 bits */
};

#define COUNT_PAGES(length)	(PAGE_CACHE_ALIGN((length)) >> PAGE_CACHE_SHIFT)

static int lz4_compress_pages_generic(struct list_head *ws,
			      struct address_space *mapping,
			      u64 start, unsigned long len,
			      struct page **pages,
			      unsigned long nr_dest_pages,
			      unsigned long *out_pages,
			      unsigned long *total_in,
			      unsigned long *total_out,
			      unsigned long max_out, int hi)
{
	/*
	 * Simplest strategy for large compression chunk support:
	 * - vmap input pages into contiguous area
	 * - preallocate desired number of output pages
	 * - vmap the output pages
	 * - compress
	 * - vunmap input, output
	 * - ???
	 * - PROFIT
	 */
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	struct compress_header_v1 hdr = { 0, 0};
	int nr_in_pages = PAGE_CACHE_ALIGN(len) >> PAGE_CACHE_SHIFT;
	/* FIXME: wasteful by 1 page up to 512k */
	unsigned long nr_out_pages = COUNT_PAGES(LZ4_compressBound(len + sizeof(hdr)));
	/* Maximum of 1M chunk: 4096 / 2 / 8 * 4096 */
	struct page **in_vmap = (struct page**)workspace->buf;
	struct page **out_vmap = (void*)in_vmap + PAGE_CACHE_SIZE / 2;
	char *data_in;
	char *data_out;
	char *data_out_start;
	int i;
	int ret;
	unsigned out_len;

	{static int xxx=0;if(!xxx){xxx=1;printk(KERN_DEBUG "lz4: using vmap, max_out %ld\n", max_out);}}

	ret = find_get_pages_contig(mapping, start >> PAGE_CACHE_SHIFT,
			nr_in_pages, in_vmap);
	BUG_ON(ret != nr_in_pages);
	data_in = vmap(in_vmap, nr_in_pages, VM_MAP, PAGE_KERNEL);
	BUG_ON(!data_in);

	for (i = 0; i < nr_out_pages; i++) {
		out_vmap[i] = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
		BUG_ON(!out_vmap[i]);
	}
	data_out = vmap(out_vmap, nr_out_pages, VM_MAP, PAGE_KERNEL);
	BUG_ON(!data_out);
	data_out_start = data_out + sizeof(struct compress_header_v1);

	if (hi) {
		LZ4_contextHC_init(workspace->mem, data_in);
		out_len = LZ4_compressHCCtx(workspace->mem, data_in,
				data_out_start, len);
		if (out_len < 0) {
			printk(KERN_ERR "btrfs: lz4 compression HC error\n");
			BUG();
		}
	} else if (len < 64 * 1024) {
		out_len = LZ4_compress64kCtx(&workspace->mem, data_in,
				data_out_start, len);
		if (out_len < 0) {
			printk(KERN_ERR "btrfs: lz4 compression 64k error\n");
			BUG();
		}
	} else {
		out_len = LZ4_compressCtx(&workspace->mem, data_in,
				data_out_start, len);
		if (out_len < 0) {
			printk(KERN_ERR "btrfs: lz4 compression error\n");
			BUG();
		}
	}

	/* Version marker, highest bits are 0100... */
	put_unaligned_le32(1 << 30 | out_len, &hdr.comp_len);
	put_unaligned_le32(len, &hdr.orig_len);
	memcpy(data_out, &hdr, sizeof(hdr));

	*total_out = out_len + sizeof(hdr);
	*total_in = len;
	*out_pages = COUNT_PAGES(*total_out);

	ret = 0;
	if (*out_pages > nr_dest_pages) {
		printk(KERN_DEBUG "lz4: pg_out %lu > %lu nr_dest, nr_out %lu; len %lu out_len %u hdr %lu, ino %lu\n",
				*out_pages, nr_dest_pages, nr_out_pages,
				len, out_len, sizeof(hdr),
				mapping->host->i_ino
				);
		printk(KERN_DEBUG "... kick the bucket\n");
		vunmap(data_in);
		for (i = 0; i < nr_in_pages; i++)
			page_cache_release(in_vmap[i]);
		vunmap(data_out);
		for (i = 0; i < *out_pages; i++)
			page_cache_release(out_vmap[i]);
		*out_pages = 0;
		return -1;
	}

	vunmap(data_in);
	for (i = 0; i < nr_in_pages; i++)
		page_cache_release(in_vmap[i]);

	vunmap(data_out);
	for (i = 0; i < min(*out_pages, nr_dest_pages); i++)
		pages[i] = out_vmap[i];
	for (; i < nr_out_pages; i++)
		__free_pages(out_vmap[i], 0);

	return ret;

	/**************************************************/
	return lz4_compress_pages_v0(ws, mapping, start, len, pages,
			nr_dest_pages, out_pages, total_in, total_out,
			max_out, hi);
}

static int lz4_compress_pages_v0(struct list_head *ws,
			      struct address_space *mapping,
			      u64 start, unsigned long len,
			      struct page **pages,
			      unsigned long nr_dest_pages,
			      unsigned long *out_pages,
			      unsigned long *total_in,
			      unsigned long *total_out,
			      unsigned long max_out, int hi)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	int ret = 0;
	char *data_in;
	char *cpage_out;
	int nr_pages = 0;
	struct page *in_page = NULL;
	struct page *out_page = NULL;
	unsigned long bytes_left;

	size_t in_len;
	size_t out_len;
	char *buf;
	unsigned long tot_in = 0;
	unsigned long tot_out = 0;
	unsigned long pg_bytes_left;
	unsigned long out_offset;
	unsigned long bytes;

	*out_pages = 0;
	*total_out = 0;
	*total_in = 0;

	in_page = find_get_page(mapping, start >> PAGE_CACHE_SHIFT);
	data_in = kmap(in_page);

	/*
	 * store the size of all chunks of compressed data in
	 * the first 4 bytes
	 */
	out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (out_page == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	cpage_out = kmap(out_page);
	out_offset = LZ4_LEN;
	tot_out = LZ4_LEN;
	pages[0] = out_page;
	nr_pages = 1;
	pg_bytes_left = PAGE_CACHE_SIZE - LZ4_LEN;

	/* compress at most one page of data each time */
	in_len = min(len, PAGE_CACHE_SIZE);
	while (tot_in < len) {
		if (hi) {
			LZ4_contextHC_init(workspace->mem, data_in);
			out_len = LZ4_compressHCCtx(workspace->mem, data_in,
					workspace->cbuf, in_len);
		} else {
			out_len = LZ4_compress64kCtx(&workspace->mem, data_in,
					workspace->cbuf, in_len);
		}
		if (out_len <= 0) {
			printk(KERN_DEBUG
				"btrfs: lz4 compress in loop returned %d\n",
			       ret);
			ret = -1;
			goto out;
		}

		/* store the size of this chunk of compressed data */
		write_compress_length(cpage_out + out_offset, out_len);
		tot_out += LZ4_LEN;
		out_offset += LZ4_LEN;
		pg_bytes_left -= LZ4_LEN;

		tot_in += in_len;
		tot_out += out_len;

		/* copy bytes from the working buffer into the pages */
		buf = workspace->cbuf;
		while (out_len) {
			bytes = min_t(unsigned long, pg_bytes_left, out_len);

			memcpy(cpage_out + out_offset, buf, bytes);

			out_len -= bytes;
			pg_bytes_left -= bytes;
			buf += bytes;
			out_offset += bytes;

			/*
			 * we need another page for writing out.
			 *
			 * Note if there's less than 4 bytes left, we just
			 * skip to a new page.
			 */
			if ((out_len == 0 && pg_bytes_left < LZ4_LEN) ||
			    pg_bytes_left == 0) {
				if (pg_bytes_left) {
					memset(cpage_out + out_offset, 0,
					       pg_bytes_left);
					tot_out += pg_bytes_left;
				}

				/* we're done, don't allocate new page */
				if (out_len == 0 && tot_in >= len)
					break;

				kunmap(out_page);
				if (nr_pages == nr_dest_pages) {
					out_page = NULL;
					ret = -1;
					goto out;
				}

				out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
				if (out_page == NULL) {
					ret = -ENOMEM;
					goto out;
				}
				cpage_out = kmap(out_page);
				pages[nr_pages++] = out_page;

				pg_bytes_left = PAGE_CACHE_SIZE;
				out_offset = 0;
			}
		}

		/* we're making it bigger, give up */
		if (tot_in > 8192 && tot_in < tot_out)
			goto out;

		/* we're all done */
		if (tot_in >= len)
			break;

		if (tot_out > max_out)
			break;

		bytes_left = len - tot_in;
		kunmap(in_page);
		page_cache_release(in_page);

		start += PAGE_CACHE_SIZE;
		in_page = find_get_page(mapping, start >> PAGE_CACHE_SHIFT);
		data_in = kmap(in_page);
		in_len = min(bytes_left, PAGE_CACHE_SIZE);
	}

	if (tot_out > tot_in)
		goto out;

	/* store the size of all chunks of compressed data */
	cpage_out = kmap(pages[0]);
	write_compress_length(cpage_out, tot_out);

	kunmap(pages[0]);

	ret = 0;
	*total_out = tot_out;
	*total_in = tot_in;
out:
	*out_pages = nr_pages;
	if (out_page)
		kunmap(out_page);

	if (in_page) {
		kunmap(in_page);
		page_cache_release(in_page);
	}

	return ret;
}

static int lz4_compress_pages(struct list_head *ws,
			      struct address_space *mapping,
			      u64 start, unsigned long len,
			      struct page **pages,
			      unsigned long nr_dest_pages,
			      unsigned long *out_pages,
			      unsigned long *total_in,
			      unsigned long *total_out,
			      unsigned long max_out)
{
	return lz4_compress_pages_generic(ws, mapping, start, len, pages,
				nr_dest_pages, out_pages, total_in, total_out,
				max_out, 0);
}

static int lz4hc_compress_pages(struct list_head *ws,
			      struct address_space *mapping,
			      u64 start, unsigned long len,
			      struct page **pages,
			      unsigned long nr_dest_pages,
			      unsigned long *out_pages,
			      unsigned long *total_in,
			      unsigned long *total_out,
			      unsigned long max_out)
{
	return lz4_compress_pages_generic(ws, mapping, start, len, pages,
				nr_dest_pages, out_pages, total_in, total_out,
				max_out, 1);
}

static int lz4_decompress_biovec(struct list_head *ws,
				 struct page **pages_in,
				 u64 disk_start,
				 struct bio_vec *bvec,
				 int vcnt,
				 size_t srclen)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	int ret = 0, ret2;
	char *data_in;
	unsigned long page_in_index = 0;
	unsigned long page_out_index = 0;
	unsigned long total_pages_in = (srclen + PAGE_CACHE_SIZE - 1) /
					PAGE_CACHE_SIZE;
	unsigned long buf_start;
	unsigned long buf_offset = 0;
	unsigned long bytes;
	unsigned long working_bytes;
	unsigned long pg_offset;

	size_t in_len;
	size_t out_len;
	unsigned long in_offset;
	unsigned long in_page_bytes_left;
	unsigned long tot_in;
	unsigned long tot_out;
	unsigned long tot_len;
	char *buf;
	bool may_late_unmap, need_unmap;

	struct page **out_vmap = (struct page**)workspace->buf;
	struct compress_header_v1 hdr;
	char *data_in_start;
	char *data_out;
	int i;

	data_in = kmap(pages_in[0]);
	tot_len = read_compress_length(data_in);

	if (tot_len <= 128 * 1024) {
		goto found_v0_container;
	}
	if (tot_len >> 30 != 1) {
		printk(KERN_ERR "btrfs: lz4 unknown container version found\n");
		BUG();
	}
	hdr.comp_len = get_unaligned_le32(data_in);
	hdr.orig_len = get_unaligned_le32(data_in + sizeof(u32));
	kunmap(pages_in[0]);
	data_in = vmap(pages_in, total_pages_in, VM_MAP, PAGE_KERNEL);
	data_in_start = data_in + sizeof(hdr);

	for (i = 0; i < vcnt; i++)
		out_vmap[i] = bvec[i].bv_page;

	data_out = vmap(out_vmap, PAGE_CACHE_ALIGN(hdr.orig_len) >> PAGE_CACHE_SHIFT,
			VM_MAP, PAGE_KERNEL);
	BUG_ON(!data_out);

	out_len = LZ4_uncompress(data_in_start, data_out, hdr.orig_len);
	if (out_len < 0) {
		printk(KERN_ERR "btrfs: lz4 decompress error\n");
		BUG();
	}

	for (i = 0; i < vcnt; i++)
		flush_dcache_page(bvec[i].bv_page);
	vunmap(data_in);
	vunmap(data_out);

	return 0;

found_v0_container:
	tot_in = LZ4_LEN;
	in_offset = LZ4_LEN;
	tot_len = min_t(size_t, srclen, tot_len);
	in_page_bytes_left = PAGE_CACHE_SIZE - LZ4_LEN;

	tot_out = 0;
	pg_offset = 0;

	while (tot_in < tot_len) {
		in_len = read_compress_length(data_in + in_offset);
		in_page_bytes_left -= LZ4_LEN;
		in_offset += LZ4_LEN;
		tot_in += LZ4_LEN;

		tot_in += in_len;
		working_bytes = in_len;
		may_late_unmap = need_unmap = false;

		/* fast path: avoid using the working buffer */
		if (in_page_bytes_left >= in_len) {
			buf = data_in + in_offset;
			bytes = in_len;
			may_late_unmap = true;
			goto cont;
		}

		/* copy bytes from the pages into the working buffer */
		buf = workspace->cbuf;
		buf_offset = 0;
		while (working_bytes) {
			bytes = min(working_bytes, in_page_bytes_left);

			memcpy(buf + buf_offset, data_in + in_offset, bytes);
			buf_offset += bytes;
cont:
			working_bytes -= bytes;
			in_page_bytes_left -= bytes;
			in_offset += bytes;

			/* check if we need to pick another page */
			if ((working_bytes == 0 && in_page_bytes_left < LZ4_LEN)
			    || in_page_bytes_left == 0) {
				tot_in += in_page_bytes_left;

				if (working_bytes == 0 && tot_in >= tot_len)
					break;

				if (page_in_index + 1 >= total_pages_in) {
					ret = -1;
					goto done;
				}

				if (may_late_unmap)
					need_unmap = true;
				else
					kunmap(pages_in[page_in_index]);

				data_in = kmap(pages_in[++page_in_index]);

				in_page_bytes_left = PAGE_CACHE_SIZE;
				in_offset = 0;
			}
		}

		out_len = LZ4_uncompress_unknownOutputSize(buf, workspace->buf,
				in_len, LZ4_CHUNK_SIZE);
		if (need_unmap)
			kunmap(pages_in[page_in_index - 1]);
		if (out_len < 0) {
			printk(KERN_WARNING "btrfs: lz4 decompress failed\n");
			ret = -1;
			break;
		}

		buf_start = tot_out;
		tot_out += out_len;

		ret2 = btrfs_decompress_buf2page(workspace->buf, buf_start,
						 tot_out, disk_start,
						 bvec, vcnt,
						 &page_out_index, &pg_offset);
		if (ret2 == 0)
			break;
	}
done:
	kunmap(pages_in[page_in_index]);
	return ret;
}

static int lz4_decompress(struct list_head *ws, unsigned char *data_in,
			  struct page *dest_page,
			  unsigned long start_byte,
			  size_t srclen, size_t destlen)
{
	struct workspace *workspace = list_entry(ws, struct workspace, list);
	size_t in_len;
	size_t out_len;
	size_t tot_len;
	int ret = 0;
	char *kaddr;
	unsigned long bytes;

	BUG_ON(srclen < LZ4_LEN);

	tot_len = read_compress_length(data_in);
	if (tot_len < 128 * 1024) {
		data_in += LZ4_LEN;
		in_len = read_compress_length(data_in);
		data_in += LZ4_LEN;

		out_len = LZ4_uncompress_unknownOutputSize(data_in, workspace->buf,
				in_len, LZ4_CHUNK_SIZE);
	} else {
		if (tot_len >> 30 != 1) {
			printk(KERN_ERR "btrfs: lz4 unknown container version found\n");
			BUG();
		}
		/* TODO: hdr? */
		in_len = get_unaligned_le32(data_in + sizeof(u32));
		out_len = LZ4_uncompress(data_in, workspace->buf, in_len);
	}

	if (out_len < 0) {
		printk(KERN_WARNING "btrfs: lz4 decompress failed\n");
		ret = -1;
		goto out;
	}

	if (out_len < start_byte) {
		ret = -1;
		goto out;
	}

	bytes = min_t(unsigned long, destlen, out_len - start_byte);

	kaddr = kmap_atomic(dest_page);
	memcpy(kaddr, workspace->buf + start_byte, bytes);
	kunmap_atomic(kaddr);
out:
	return ret;
}

struct btrfs_compress_op btrfs_lz4_compress = {
	.alloc_workspace	= lz4_alloc_workspace,
	.free_workspace		= lz4_free_workspace,
	.compress_pages		= lz4_compress_pages,
	.decompress_biovec	= lz4_decompress_biovec,
	.decompress		= lz4_decompress,
};

struct btrfs_compress_op btrfs_lz4hc_compress = {
	.alloc_workspace	= lz4hc_alloc_workspace,
	.free_workspace		= lz4_free_workspace,
	.compress_pages		= lz4hc_compress_pages,
	.decompress_biovec	= lz4_decompress_biovec,
	.decompress		= lz4_decompress,
};
