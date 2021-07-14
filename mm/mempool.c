// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/mempool.c
 *
 *  memory buffer pool support. Such pools are mostly used
 *  for guaranteed, deadlock-free memory allocations during
 *  extreme VM load.
 *
 *  started by Ingo Molnar, Copyright (C) 2001
 *  debugging by David Rientjes, Copyright (C) 2015
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/kasan.h>
#include <linux/kmemleak.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include "slab.h"

#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
static void poison_error(mempool_t *pool, void *element, size_t size,
			 size_t byte)
{
	const int nr = pool->curr_nr;
	const int start = max_t(int, byte - (BITS_PER_LONG / 8), 0);
	const int end = min_t(int, byte + (BITS_PER_LONG / 8), size);
	int i;

	pr_err("BUG: mempool element poison mismatch\n");
	pr_err("Mempool %p size %zu\n", pool, size);
	pr_err(" nr=%d @ %p: %s0x", nr, element, start > 0 ? "... " : "");
	for (i = start; i < end; i++)
		pr_cont("%x ", *(u8 *)(element + i));
	pr_cont("%s\n", end < size ? "..." : "");
	dump_stack();
}

static void __check_element(mempool_t *pool, void *element, size_t size)
{
	u8 *obj = element;
	size_t i;

	for (i = 0; i < size; i++) {
		u8 exp = (i < size - 1) ? POISON_FREE : POISON_END;

		if (obj[i] != exp) {
			poison_error(pool, element, size, i);
			return;
		}
	}
	memset(obj, POISON_INUSE, size);
}

static void check_element(mempool_t *pool, void *element)
{
	/* Mempools backed by slab allocator */
	if (pool->free == mempool_free_slab || pool->free == mempool_kfree)
		__check_element(pool, element, ksize(element));

	/* Mempools backed by page allocator */
	if (pool->free == mempool_free_pages) {
		int order = (int)(long)pool->pool_data;
		void *addr = kmap_atomic((struct page *)element);

		__check_element(pool, addr, 1UL << (PAGE_SHIFT + order));
		kunmap_atomic(addr);
	}
}

static void __poison_element(void *element, size_t size)
{
	u8 *obj = element;

	memset(obj, POISON_FREE, size - 1);
	obj[size - 1] = POISON_END;
}

static void poison_element(mempool_t *pool, void *element)
{
	/* Mempools backed by slab allocator */
	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
		__poison_element(element, ksize(element));

	/* Mempools backed by page allocator */
	if (pool->alloc == mempool_alloc_pages) {
		int order = (int)(long)pool->pool_data;
		void *addr = kmap_atomic((struct page *)element);

		__poison_element(addr, 1UL << (PAGE_SHIFT + order));
		kunmap_atomic(addr);
	}
}
#else /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
static inline void check_element(mempool_t *pool, void *element)
{
}
static inline void poison_element(mempool_t *pool, void *element)
{
}
#endif /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */

static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
{
	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
		kasan_poison_kfree(element, _RET_IP_);
	if (pool->alloc == mempool_alloc_pages)
		kasan_free_pages(element, (unsigned long)pool->pool_data);
}

static void kasan_unpoison_element(mempool_t *pool, void *element)
{
	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
		kasan_unpoison_slab(element);
	if (pool->alloc == mempool_alloc_pages)
		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
}

static __always_inline void add_element(mempool_t *pool, void *element)
{
	BUG_ON(pool->curr_nr >= pool->min_nr);
	poison_element(pool, element);
	kasan_poison_element(pool, element);
	pool->elements[pool->curr_nr++] = element;
}

static void *remove_element(mempool_t *pool)
{
	void *element = pool->elements[--pool->curr_nr];

	BUG_ON(pool->curr_nr < 0);
	kasan_unpoison_element(pool, element);
	check_element(pool, element);
	return element;
}

/**
 * mempool_exit - exit a mempool initialized with mempool_init()
 * @pool:      pointer to the memory pool which was initialized with
 *             mempool_init().
 *
 * Free all reserved elements in @pool and @pool itself.  This function
 * only sleeps if the free_fn() function sleeps.
 *
 * May be called on a zeroed but uninitialized mempool (i.e. allocated with
 * kzalloc()).
 */
void mempool_exit(mempool_t *pool)
{
	while (pool->curr_nr) {
		void *element = remove_element(pool);//把elements指针数组中的内存移除
		pool->free(element, pool->pool_data);//释放elements数组中的所有对象
	}
	kfree(pool->elements);//销毁elements指针数组
	pool->elements = NULL;
}
EXPORT_SYMBOL(mempool_exit);

/**
 * mempool_destroy - deallocate a memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * Free all reserved elements in @pool and @pool itself.  This function
 * only sleeps if the free_fn() function sleeps.
 */
//销毁一个内存池
void mempool_destroy(mempool_t *pool)
{
	if (unlikely(!pool))
		return;

	mempool_exit(pool);//释放内存池中的内存块
	kfree(pool);//释放内存池结构体
}
EXPORT_SYMBOL(mempool_destroy);

int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
		      mempool_free_t *free_fn, void *pool_data,
		      gfp_t gfp_mask, int node_id)
{
	//初始化内存池的相关参数
	spin_lock_init(&pool->lock);//初始化锁
	pool->min_nr	= min_nr;
	pool->pool_data = pool_data;
	pool->alloc	= alloc_fn;
	pool->free	= free_fn;
	init_waitqueue_head(&pool->wait);//初始化等待队列

	//分配一个长度为min_nr的数组用于存放申请后对象的指针
	pool->elements = kmalloc_array_node(min_nr, sizeof(void *),
					    gfp_mask, node_id);
	if (!pool->elements)
		return -ENOMEM;

	/*
	 * First pre-allocate the guaranteed number of buffers.
	 */
	//首先保证预分配的缓冲区数量
	while (pool->curr_nr < pool->min_nr) {
		void *element;

		//调用pool->alloc函数min_nr次
		element = pool->alloc(gfp_mask, pool->pool_data);
		if (unlikely(!element)) {//如果申请不到element，则直接销毁此内存池
			mempool_exit(pool);
			return -ENOMEM;
		}
		add_element(pool, element);//添加到elements指针数组中
	}

	return 0;
}
EXPORT_SYMBOL(mempool_init_node);

/**
 * mempool_init - initialize a memory pool
 * @pool:      pointer to the memory pool that should be initialized
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * Like mempool_create(), but initializes the pool in (i.e. embedded in another
 * structure).
 */
int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
		 mempool_free_t *free_fn, void *pool_data)
{
	return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
				 pool_data, GFP_KERNEL, NUMA_NO_NODE);

}
EXPORT_SYMBOL(mempool_init);

/**
 * mempool_create - create a memory pool
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * this function creates and allocates a guaranteed size, preallocated
 * memory pool. The pool can be used from the mempool_alloc() and mempool_free()
 * functions. This function might sleep. Both the alloc_fn() and the free_fn()
 * functions might sleep - as long as the mempool_alloc() function is not called
 * from IRQ contexts.
 */
 //创建一个内存池对象
mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
				mempool_free_t *free_fn, void *pool_data)
{
	return mempool_create_node(min_nr,alloc_fn,free_fn, pool_data,
				   GFP_KERNEL, NUMA_NO_NODE);
}
EXPORT_SYMBOL(mempool_create);

/******************
创建一个内存池对象
参数：
min_nr ： 	为内存池分配的最小内存成员数量
alloc_fn ： 用户自定义内存分配函数(可以使用系统定义函数)
free_fn :	用户自定义内存释放函数(可以使用系统定义函数)
pool.data ：根据用户自定义内存分配函数所提供的可选私有数据，一般是缓存区指针
gfp_mask ： 内存分配掩码
node_id ： 	内存节点的id
******************/
mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			       mempool_free_t *free_fn, void *pool_data,
			       gfp_t gfp_mask, int node_id)
{
	mempool_t *pool;

	//为内存池对象分配内存
	pool = kzalloc_node(sizeof(*pool), gfp_mask, node_id);
	if (!pool)
		return NULL;

	//初始化内存池
	if (mempool_init_node(pool, min_nr, alloc_fn, free_fn, pool_data,
			      gfp_mask, node_id)) {
		kfree(pool);
		return NULL;
	}

	return pool;//返回内存池结构体
}
EXPORT_SYMBOL(mempool_create_node);

/**
 * mempool_resize - resize an existing memory pool
 * @pool:       pointer to the memory pool which was allocated via
 *              mempool_create().
 * @new_min_nr: the new minimum number of elements guaranteed to be
 *              allocated for this pool.
 *
 * This function shrinks/grows the pool. In the case of growing,
 * it cannot be guaranteed that the pool will be grown to the new
 * size immediately, but new mempool_free() calls will refill it.
 * This function may sleep.
 *
 * Note, the caller must guarantee that no mempool_destroy is called
 * while this function is running. mempool_alloc() & mempool_free()
 * might be called (eg. from IRQ contexts) while this function executes.
 */
int mempool_resize(mempool_t *pool, int new_min_nr)
{
	void *element;
	void **new_elements;
	unsigned long flags;

	BUG_ON(new_min_nr <= 0);
	might_sleep();

	spin_lock_irqsave(&pool->lock, flags);
	if (new_min_nr <= pool->min_nr) {
		while (new_min_nr < pool->curr_nr) {
			element = remove_element(pool);
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(element, pool->pool_data);
			spin_lock_irqsave(&pool->lock, flags);
		}
		pool->min_nr = new_min_nr;
		goto out_unlock;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	/* Grow the pool */
	new_elements = kmalloc_array(new_min_nr, sizeof(*new_elements),
				     GFP_KERNEL);
	if (!new_elements)
		return -ENOMEM;

	spin_lock_irqsave(&pool->lock, flags);
	if (unlikely(new_min_nr <= pool->min_nr)) {
		/* Raced, other resize will do our work */
		spin_unlock_irqrestore(&pool->lock, flags);
		kfree(new_elements);
		goto out;
	}
	memcpy(new_elements, pool->elements,
			pool->curr_nr * sizeof(*new_elements));
	kfree(pool->elements);
	pool->elements = new_elements;
	pool->min_nr = new_min_nr;

	while (pool->curr_nr < pool->min_nr) {
		spin_unlock_irqrestore(&pool->lock, flags);
		element = pool->alloc(GFP_KERNEL, pool->pool_data);
		if (!element)
			goto out;
		spin_lock_irqsave(&pool->lock, flags);
		if (pool->curr_nr < pool->min_nr) {
			add_element(pool, element);
		} else {
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(element, pool->pool_data);	/* Raced */
			goto out;
		}
	}
out_unlock:
	spin_unlock_irqrestore(&pool->lock, flags);
out:
	return 0;
}
EXPORT_SYMBOL(mempool_resize);

/**
 * mempool_alloc - allocate an element from a specific memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 * @gfp_mask:  the usual allocation bitmask.
 *
 * this function only sleeps if the alloc_fn() function sleeps or
 * returns NULL. Note that due to preallocation, this function
 * *never* fails when called from process contexts. (it might
 * fail if called from an IRQ context.)
 * Note: using __GFP_ZERO is not supported.
 */
//内存池分配对象
void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	void *element;
	unsigned long flags;
	wait_queue_entry_t wait;
	gfp_t gfp_temp;

	//形参gfp_mask中不能包含_GFP_ZERO
	VM_WARN_ON_ONCE(gfp_mask & __GFP_ZERO);
	
	//如果有__GFP_WAIT标志，则会先阻塞，切换进程
	//#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
	might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

	gfp_mask |= __GFP_NOMEMALLOC;//不使用预留内存
	gfp_mask |= __GFP_NORETRY;//分配页时如果失败则返回，不进行重试
	gfp_mask |= __GFP_NOWARN;//分配失败不提供警告

	//gfp_mask只保留__GFP_DIRECT_RECLAIM和__GFP_IO标志
	gfp_temp = gfp_mask & ~(__GFP_DIRECT_RECLAIM|__GFP_IO);

repeat_alloc:

	//使用内存池中的alloc函数进行分配对象
	element = pool->alloc(gfp_temp, pool->pool_data);
	if (likely(element != NULL))
		return element;

	//给内存池上锁，获取后此段临界区禁止中断和抢占
	spin_lock_irqsave(&pool->lock, flags);
	
	//如果当前内存池中有空闲数量
	if (likely(pool->curr_nr)) {
		element = remove_element(pool);//从内存池中获取内存对象
		spin_unlock_irqrestore(&pool->lock, flags);//解锁
		/* paired with rmb in mempool_free(), read comment there */
		smp_wmb();//写内存屏障，保证之前的写操作已经完成
		/*
		 * Update the allocation stack trace as this is more useful
		 * for debugging.
		 */
		kmemleak_update_trace(element);//用于debug
		return element;
	}

	/*
	 * We use gfp mask w/o direct reclaim or IO for the first round.  If
	 * alloc failed with that and @pool was empty, retry immediately.
	 */
	//这里是内存池中也没有空闲内存对象的时候进行的操作
	
	//如果gfp_temp != gfp_mask
	if (gfp_temp != gfp_mask) {
		spin_unlock_irqrestore(&pool->lock, flags);
		gfp_temp = gfp_mask;
		goto repeat_alloc;//跳到repeat_alloc重新获取一次
	}

	/* We must not sleep if !__GFP_DIRECT_RECLAIM */
	//传入的参数gfp_mask不允许回收的等待，分配不到内存则直接退出
	if (!(gfp_mask & __GFP_DIRECT_RECLAIM)) {
		spin_unlock_irqrestore(&pool->lock, flags);
		return NULL;
	}

	/* Let's wait for someone else to return an element to @pool */
	init_wait(&wait);//初始化wait等待进程
	//加入到内存池的等待队列中，等待当内存池中有空闲对象或者等待超时
	prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);

	spin_unlock_irqrestore(&pool->lock, flags);

	/*
	 * FIXME: this should be io_schedule().  The timeout is there as a
	 * workaround for some DM problems in 2.6.18.
	 */
	io_schedule_timeout(5*HZ);//阻塞等待5秒

	finish_wait(&pool->wait, &wait);//从内存池的等待队列删除此进程
	goto repeat_alloc;//跳转到repeat_alloc，重新尝试获取内存对象
}
EXPORT_SYMBOL(mempool_alloc);

/**
 * mempool_free - return an element to the pool.
 * @element:   pool element pointer.
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * this function only sleeps if the free_fn() function sleeps.
 */
// 内存池释放内存对象操作
void mempool_free(void *element, mempool_t *pool)
{
	unsigned long flags;

	//传入的对象为空，则直接退出
	if (unlikely(element == NULL))
		return;

	/*
	 * Paired with the wmb in mempool_alloc().  The preceding read is
	 * for @element and the following @pool->curr_nr.  This ensures
	 * that the visible value of @pool->curr_nr is from after the
	 * allocation of @element.  This is necessary for fringe cases
	 * where @element was passed to this task without going through
	 * barriers.
	 *
	 * For example, assume @p is %NULL at the beginning and one task
	 * performs "p = mempool_alloc(...);" while another task is doing
	 * "while (!p) cpu_relax(); mempool_free(p, ...);".  This function
	 * may end up using curr_nr value which is from before allocation
	 * of @p without the following rmb.
	 */
	smp_rmb();//读内存屏障

	/*
	 * For correctness, we need a test which is guaranteed to trigger
	 * if curr_nr + #allocated == min_nr.  Testing curr_nr < min_nr
	 * without locking achieves that and refilling as soon as possible
	 * is desirable.
	 *
	 * Because curr_nr visible here is always a value after the
	 * allocation of @element, any task which decremented curr_nr below
	 * min_nr is guaranteed to see curr_nr < min_nr unless curr_nr gets
	 * incremented to min_nr afterwards.  If curr_nr gets incremented
	 * to min_nr after the allocation of @element, the elements
	 * allocated after that are subject to the same guarantee.
	 *
	 * Waiters happen iff curr_nr is 0 and the above guarantee also
	 * ensures that there will be frees which return elements to the
	 * pool waking up the waiters.
	 */
	//如果当前内存池中空闲的内存对象少于内存池中应当保存的内存对象的数量时，优先把释放的对象加入到内存池空闲数组中
	if (unlikely(pool->curr_nr < pool->min_nr)) {
		spin_lock_irqsave(&pool->lock, flags);
		if (likely(pool->curr_nr < pool->min_nr)) {
			add_element(pool, element);//将用户释放的element重新加到缓存而当中
			spin_unlock_irqrestore(&pool->lock, flags);
			wake_up(&pool->wait);//唤醒等待队列，目前已经有人释放内存，可以再次申请这个内存来使用
			return;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}
	pool->free(element, pool->pool_data);//直接调用释放函数
}
EXPORT_SYMBOL(mempool_free);

/*
 * A commonly used alloc and free fn.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	VM_BUG_ON(mem->ctor);
	return kmem_cache_alloc(mem, gfp_mask);
}
EXPORT_SYMBOL(mempool_alloc_slab);

void mempool_free_slab(void *element, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	kmem_cache_free(mem, element);
}
EXPORT_SYMBOL(mempool_free_slab);

/*
 * A commonly used alloc and free fn that kmalloc/kfrees the amount of memory
 * specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
{
	size_t size = (size_t)pool_data;
	return kmalloc(size, gfp_mask);
}
EXPORT_SYMBOL(mempool_kmalloc);

void mempool_kfree(void *element, void *pool_data)
{
	kfree(element);
}
EXPORT_SYMBOL(mempool_kfree);

/*
 * A simple mempool-backed page allocator that allocates pages
 * of the order specified by pool_data.
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
{
	int order = (int)(long)pool_data;
	return alloc_pages(gfp_mask, order);
}
EXPORT_SYMBOL(mempool_alloc_pages);

void mempool_free_pages(void *element, void *pool_data)
{
	int order = (int)(long)pool_data;
	__free_pages(element, order);
}
EXPORT_SYMBOL(mempool_free_pages);
