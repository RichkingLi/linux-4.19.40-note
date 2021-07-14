/* SPDX-License-Identifier: GPL-2.0 */
/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/wait.h>
#include <linux/compiler.h>

struct kmem_cache;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

typedef struct mempool_s {
	spinlock_t lock;//防止多处理器并发而引入的锁
	
	int min_nr;	//最大元素个数，也是初始个数，当内存池被创建时，会调用alloc函数申请此变量相应数量的slab放到elements指向的指针数组中
	int curr_nr;//当前元素个数，elements数组中空闲的成员数量
	void **elements;//用来存放内存成员的二维数组，等于elements[min_nr][内存对象的长度]

	void *pool_data;//内存池的拥有者的私有数据结构(这个指针专门用来指向内存对象对应的缓存区的指针)
	mempool_alloc_t *alloc;//内存分配函数
	mempool_free_t *free;//内存释放函数
	wait_queue_head_t wait;//当内存池为空时使用的等待队列，当内存池中空闲内存对象为空时，获取函数会将当前进程阻塞，直到超时或者有空闲内存对象时才会唤醒
} mempool_t;

static inline bool mempool_initialized(mempool_t *pool)
{
	return pool->elements != NULL;
}

void mempool_exit(mempool_t *pool);
int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
		      mempool_free_t *free_fn, void *pool_data,
		      gfp_t gfp_mask, int node_id);
int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
		 mempool_free_t *free_fn, void *pool_data);

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);
extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data,
			gfp_t gfp_mask, int nid);

extern int mempool_resize(mempool_t *pool, int new_min_nr);
extern void mempool_destroy(mempool_t *pool);
extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab cache that is passed in through pool_data.
 * Note: the slab cache may not have a ctor function.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);

static inline int
mempool_init_slab_pool(mempool_t *pool, int min_nr, struct kmem_cache *kc)
{
	return mempool_init(pool, min_nr, mempool_alloc_slab,
			    mempool_free_slab, (void *) kc);
}

static inline mempool_t *
mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
{
	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
			      (void *) kc);
}

/*
 * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
 * amount of memory specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
void mempool_kfree(void *element, void *pool_data);

static inline int mempool_init_kmalloc_pool(mempool_t *pool, int min_nr, size_t size)
{
	return mempool_init(pool, min_nr, mempool_kmalloc,
			    mempool_kfree, (void *) size);
}

static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
{
	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
			      (void *) size);
}

/*
 * A mempool_alloc_t and mempool_free_t for a simple page allocator that
 * allocates pages of the order specified by pool_data
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
void mempool_free_pages(void *element, void *pool_data);

static inline int mempool_init_page_pool(mempool_t *pool, int min_nr, int order)
{
	return mempool_init(pool, min_nr, mempool_alloc_pages,
			    mempool_free_pages, (void *)(long)order);
}

static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
{
	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
			      (void *)(long)order);
}

#endif /* _LINUX_MEMPOOL_H */
