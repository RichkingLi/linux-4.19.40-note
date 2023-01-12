/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/mm_types_task.h>

#include <linux/auxvec.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/uprobes.h>
#include <linux/page-flags-layout.h>
#include <linux/workqueue.h>

#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

typedef int vm_fault_t;

struct address_space;
struct mem_cgroup;
struct hmm;

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * If you allocate the page using alloc_pages(), you can use some of the
 * space in struct page for your own purposes.  The five words in the main
 * union are available, except for bit 0 of the first word which must be
 * kept clear.  Many users use this word to store a pointer to an object
 * which is guaranteed to be aligned.  If you use the same storage as
 * page->mapping, you must restore it to NULL before freeing the page.
 *
 * If your page will not be mapped to userspace, you can also use the four
 * bytes in the mapcount union, but you must call page_mapcount_reset()
 * before freeing it.
 *
 * If you want to use the refcount field, it must be used in such a way
 * that other CPUs temporarily incrementing and then decrementing the
 * refcount does not cause problems.  On receiving the page from
 * alloc_pages(), the refcount will be positive.
 *
 * If you allocate pages of order > 0, you can use some of the fields
 * in each subpage, but you may need to restore some of their values
 * afterwards.
 *
 * SLUB uses cmpxchg_double() to atomically update its freelist and
 * counters.  That requires that freelist & counters be adjacent and
 * double-word aligned.  We align all struct pages to double-word
 * boundaries, and ensure that 'freelist' is aligned within the
 * struct.
 */
#ifdef CONFIG_HAVE_ALIGNED_STRUCT_PAGE
#define _struct_page_alignment	__aligned(2 * sizeof(unsigned long))
#else
#define _struct_page_alignment
#endif
//用于页描述符，一组标志(如PG_locked、PG_error)，同时页框所在的管理区和node的编号也保存在当中
struct page {
    /* 在lru算法中主要用到的标志flags
     * PG_active: 表示此页当前是否活跃，当放到或者准备放到活动lru链表时，被置位
     * PG_referenced: 表示此页最近是否被访问，每次页面访问都会被置位
     * PG_lru: 表示此页是处于lru链表中的
     * PG_mlocked: 表示此页被mlock()锁在内存中，禁止换出和释放
     * PG_swapbacked: 表示此页依靠swap，可能是进程的匿名页(堆、栈、数据段)，匿名mmap共享内存映射，shmem共享内存映射
     */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * zone_lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			struct list_head lru;
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			pgoff_t index;		/* Our offset within mapping. */
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			unsigned long private;
		};
		struct {	/* slab, slob and slub */
			union {
				struct list_head slab_list;	/* uses lru */
				struct {	/* Partial pages */
					struct page *next;
#ifdef CONFIG_64BIT
					int pages;	/* Nr of pages left */
					int pobjects;	/* Approximate count */
#else
					short int pages;
					short int pobjects;
#endif
				};
			};
			struct kmem_cache *slab_cache; /* not slob */
			/* Double-word boundary */
			void *freelist;		/* first free object */
			union {
				void *s_mem;	/* slab: first object */
				unsigned long counters;		/* SLUB */
				struct {			/* SLUB */
					unsigned inuse:16;
					unsigned objects:15;
					unsigned frozen:1;
				};
			};
		};
		struct {	/* Tail pages of compound page */
			unsigned long compound_head;	/* Bit zero is set */

			/* First tail page only */
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
		};
		struct {	/* Second tail page of compound page */
			unsigned long _compound_pad_1;	/* compound_head */
			unsigned long _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {	/* Page table pages */
			unsigned long _pt_pad_1;	/* compound_head */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
			unsigned long _pt_pad_2;	/* mapping */
			union {
				struct mm_struct *pt_mm; /* x86 pgds only */
				atomic_t pt_frag_refcount; /* powerpc */
			};
#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl;
#else
			spinlock_t ptl;
#endif
		};
		struct {	/* ZONE_DEVICE pages */
			/** @pgmap: Points to the hosting device page map. */
			struct dev_pagemap *pgmap;
			unsigned long hmm_data;
			unsigned long _zd_pad_1;	/* uses mapping */
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
	};

	union {		/* This union is 4 bytes in size. */
		/*
		 * If the page can be mapped to userspace, encodes the number
		 * of times this page is referenced by a page table.
		 */
		atomic_t _mapcount;//内存管理子系统中映射的页表项计数，用于表示页是否已经映射

		/*
		 * If the page is neither PageSlab nor mappable to userspace,
		 * the value stored here may help determine what this page
		 * is used for.  See page-flags.h for a list of page types
		 * which are currently stored here.
		 */
		unsigned int page_type;

		unsigned int active;		/* SLAB */
		int units;			/* SLOB */
	};

	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
	atomic_t _refcount;

#ifdef CONFIG_MEMCG
	struct mem_cgroup *mem_cgroup;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
} _struct_page_alignment;

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

struct page_frag_cache {
	void * va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size;
#else
	__u32 offset;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_refcount every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
	bool pfmemalloc;
};

typedef unsigned long vm_flags_t;

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	vm_flags_t	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	int		vm_usage;	/* region usage count (access under nommu_region_sem) */
	bool		vm_icache_flushed : 1; /* true if the icache has been flushed for
						* this region */
};

#ifdef CONFIG_USERFAULTFD
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};
#else /* CONFIG_USERFAULTFD */
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) {})
struct vm_userfaultfd_ctx {};
#endif /* CONFIG_USERFAULTFD */

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	//这两个成员分别保存该虚拟内存空间的首地址和末地址后第一个字节的地址
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;//分别是VMA链表的前后成员

	struct rb_node vm_rb;//如果使用链表结构，会影响他搜索的速度，采用红黑树可以解决此问题，
	//每一个进程结构体里面的mm_struct都会创建一颗红黑树，将VMA作为一个节点加入红黑树中，提升搜索速率	

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	struct mm_struct *vm_mm;	//内存描述符，也就是虚拟内存区域所属的用户虚拟地址空间
	pgprot_t vm_page_prot;		//保护位，也就是访问权限
	
	/* Flags, see mm.h
	#define VM_NONE		0x00000000
	#define VM_READ		0x00000001	
	#define VM_WRITE	0x00000002
	#define VM_EXEC		0x00000004
	#define VM_SHARED	0x00000008		*/
	unsigned long vm_flags;		//保护标志位


	//为了支持查询一个文件区间被映射到哪些虚拟内存区域，
	//把一个文件映射的所有虚拟内存区域加入该文件地址空间结构体的i_mmap成员（address_space->i_mmap）所指向的设备树。
	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	 //把虚拟内存区域关联的所有的anon_vma实例串联起来，
	 //一个虚拟内存区域会关联到父进程的anon_vma实例和自己的anon_vma实例
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	//指向一个anon_vma实例，结构体anon_vma用来组织匿名页被映射到的所有的虚拟地址空间
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;//虚拟内存操作函数集合，定义的结构体在mm.h文件中

	/* Information about our backing store: */
	unsigned long vm_pgoff;//文件偏移，单位是页
					   units */
	struct file * vm_file;//指向内存区的文件映射，如果是私有的匿名映射，该成员为NULL
	void * vm_private_data;//指向内存区的私有数据

	atomic_long_t swap_readahead_info;
#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
} __randomize_layout;

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct kioctx_table;
struct mm_struct {
	struct {
		struct vm_area_struct *mmap;//虚拟内存区域链表
		struct rb_root mm_rb;//虚拟内存区域红黑树	
		u64 vmacache_seqnum; //信号量，表示vma是否在cache中/* per-thread vmacache */
#ifdef CONFIG_MMU
		unsigned long (*get_unmapped_area) (struct file *filp,//在内存映射区域找到一块没有映射的区域
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
		unsigned long mmap_base;//内存映射区域的起始地址
		unsigned long mmap_legacy_base;	/* base of mmap area in bottom-up allocations */
#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
		/* Base adresses for compatible mmap() */
		unsigned long mmap_compat_base;
		unsigned long mmap_compat_legacy_base;
#endif
		unsigned long task_size;//用户虚拟地址空间长度
		unsigned long highest_vm_end;	/* highest vma end address */
		pgd_t * pgd;//指向页全局目录，也就是第一级页表

		/**
		 * @mm_users: The number of users including userspace.
		 *
		 * Use mmget()/mmget_not_zero()/mmput() to modify. When this
		 * drops to 0 (i.e. when the task exits and there are no other
		 * temporary reference holders), we also release a reference on
		 * @mm_count (which may then free the &struct mm_struct if
		 * @mm_count also drops to 0).
		 */
		atomic_t mm_users;//共享一个用户虚拟地址空间的进程数量，也就是线程包含的进程数量

		/**
		 * @mm_count: The number of references to &struct mm_struct
		 * (@mm_users count as 1).
		 *
		 * Use mmgrab()/mmdrop() to modify. When this drops to 0, the
		 * &struct mm_struct is freed.
		 */
		atomic_t mm_count;//内存描述符的引用计数

#ifdef CONFIG_MMU
		atomic_long_t pgtables_bytes;//PTE页表页大小
#endif
		int map_count;//虚拟内存映射数量

		spinlock_t page_table_lock;//保护页表的锁
		/* Protects page tables and some
					     * counters
					     */
		struct rw_semaphore mmap_sem;

		struct list_head mmlist; //链表指向可能进行了交换的内存
		/* List of maybe swapped mm's.	These
					  * are globally strung together off
					  * init_mm.mmlist, and are protected
					  * by mmlist_lock
					  */


		unsigned long hiwater_rss;//RSS的高水位使用情况
		unsigned long hiwater_vm;//高水位虚拟内存使用情况

		unsigned long total_vm;//进程地址空间的映射页数
		unsigned long locked_vm;//被锁住不能换出的页数
		unsigned long pinned_vm;//不能换出也不能移动的页数
		unsigned long data_vm;//存放数据的页数
		unsigned long exec_vm;//存放可执行文件的页数
		unsigned long stack_vm;//存放栈的页数
		unsigned long def_flags;

		spinlock_t arg_lock; /* protect the below fields */
		
		//可执行程序代码段的起始地址和结束地址，数据段的起始地址和结束地址
		unsigned long start_code, end_code, start_data, end_data;
		//堆的起始地址，堆的当前地址（也是结束地址），栈的起始地址（栈的结束地址在寄存器的栈顶指针中）
		unsigned long start_brk, brk, start_stack;
		//参数字符串的起始地址和结束地址，环境变量的其实地址和结束地址
		unsigned long arg_start, arg_end, env_start, env_end;

		unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

		/*
		 * Special counters, in some configurations protected by the
		 * page_table_lock, in other configurations by being atomic.
		 */
		struct mm_rss_stat rss_stat;

		struct linux_binfmt *binfmt;

		/* Architecture-specific MM context */
		mm_context_t context;//处理器架构特定的内存瓜茉莉上下文

		unsigned long flags; /* Must use atomic bitops to access */

		struct core_state *core_state; /* coredumping support */
#ifdef CONFIG_MEMBARRIER
		atomic_t membarrier_state;
#endif
#ifdef CONFIG_AIO
		spinlock_t			ioctx_lock;
		struct kioctx_table __rcu	*ioctx_table;
#endif
#ifdef CONFIG_MEMCG
		/*
		 * "owner" points to a task that is regarded as the canonical
		 * user/owner of this mm. All of the following must be true in
		 * order for it to be changed:
		 *
		 * current == mm->owner
		 * current->mm != mm
		 * new_owner->mm == mm
		 * new_owner->alloc_lock is held
		 */
		struct task_struct __rcu *owner;
#endif
		struct user_namespace *user_ns;

		/* store ref to file /proc/<pid>/exe symlink points to */
		struct file __rcu *exe_file;
#ifdef CONFIG_MMU_NOTIFIER
		struct mmu_notifier_mm *mmu_notifier_mm;
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
		pgtable_t pmd_huge_pte; /* protected by page_table_lock */
#endif
#ifdef CONFIG_NUMA_BALANCING
		/*
		 * numa_next_scan is the next time that the PTEs will be marked
		 * pte_numa. NUMA hinting faults will gather statistics and
		 * migrate pages to new nodes if necessary.
		 */
		unsigned long numa_next_scan;

		/* Restart point for scanning and setting pte_numa */
		unsigned long numa_scan_offset;

		/* numa_scan_seq prevents two threads setting pte_numa */
		int numa_scan_seq;
#endif
		/*
		 * An operation with batched TLB flushing is going on. Anything
		 * that can move process memory needs to flush the TLB when
		 * moving a PROT_NONE or PROT_NUMA mapped page.
		 */
		atomic_t tlb_flush_pending;
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
		/* See flush_tlb_batched_pending() */
		bool tlb_flush_batched;
#endif
		struct uprobes_state uprobes_state;
#ifdef CONFIG_HUGETLB_PAGE
		atomic_long_t hugetlb_usage;
#endif
		struct work_struct async_put_work;

#if IS_ENABLED(CONFIG_HMM)
		/* HMM needs to track a few things per mm */
		struct hmm *hmm;
#endif
	} __randomize_layout;

	/*
	 * The mm_cpumask needs to be at the end of mm_struct, because it
	 * is dynamically sized based on nr_cpu_ids.
	 */
	unsigned long cpu_bitmap[];
};

extern struct mm_struct init_mm;

/* Pointer magic because the dynamic array size confuses some compilers. */
static inline void mm_init_cpumask(struct mm_struct *mm)
{
	unsigned long cpu_bitmap = (unsigned long)mm;

	cpu_bitmap += offsetof(struct mm_struct, cpu_bitmap);
	cpumask_clear((struct cpumask *)cpu_bitmap);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return (struct cpumask *)&mm->cpu_bitmap;
}

struct mmu_gather;
extern void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm,
				unsigned long start, unsigned long end);
extern void tlb_finish_mmu(struct mmu_gather *tlb,
				unsigned long start, unsigned long end);

static inline void init_tlb_flush_pending(struct mm_struct *mm)
{
	atomic_set(&mm->tlb_flush_pending, 0);
}

static inline void inc_tlb_flush_pending(struct mm_struct *mm)
{
	atomic_inc(&mm->tlb_flush_pending);
	/*
	 * The only time this value is relevant is when there are indeed pages
	 * to flush. And we'll only flush pages after changing them, which
	 * requires the PTL.
	 *
	 * So the ordering here is:
	 *
	 *	atomic_inc(&mm->tlb_flush_pending);
	 *	spin_lock(&ptl);
	 *	...
	 *	set_pte_at();
	 *	spin_unlock(&ptl);
	 *
	 *				spin_lock(&ptl)
	 *				mm_tlb_flush_pending();
	 *				....
	 *				spin_unlock(&ptl);
	 *
	 *	flush_tlb_range();
	 *	atomic_dec(&mm->tlb_flush_pending);
	 *
	 * Where the increment if constrained by the PTL unlock, it thus
	 * ensures that the increment is visible if the PTE modification is
	 * visible. After all, if there is no PTE modification, nobody cares
	 * about TLB flushes either.
	 *
	 * This very much relies on users (mm_tlb_flush_pending() and
	 * mm_tlb_flush_nested()) only caring about _specific_ PTEs (and
	 * therefore specific PTLs), because with SPLIT_PTE_PTLOCKS and RCpc
	 * locks (PPC) the unlock of one doesn't order against the lock of
	 * another PTL.
	 *
	 * The decrement is ordered by the flush_tlb_range(), such that
	 * mm_tlb_flush_pending() will not return false unless all flushes have
	 * completed.
	 */
}

static inline void dec_tlb_flush_pending(struct mm_struct *mm)
{
	/*
	 * See inc_tlb_flush_pending().
	 *
	 * This cannot be smp_mb__before_atomic() because smp_mb() simply does
	 * not order against TLB invalidate completion, which is what we need.
	 *
	 * Therefore we must rely on tlb_flush_*() to guarantee order.
	 */
	atomic_dec(&mm->tlb_flush_pending);
}

static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	/*
	 * Must be called after having acquired the PTL; orders against that
	 * PTLs release and therefore ensures that if we observe the modified
	 * PTE we must also observe the increment from inc_tlb_flush_pending().
	 *
	 * That is, it only guarantees to return true if there is a flush
	 * pending for _this_ PTL.
	 */
	return atomic_read(&mm->tlb_flush_pending);
}

static inline bool mm_tlb_flush_nested(struct mm_struct *mm)
{
	/*
	 * Similar to mm_tlb_flush_pending(), we must have acquired the PTL
	 * for which there is a TLB flush pending in order to guarantee
	 * we've seen both that PTE modification and the increment.
	 *
	 * (no requirement on actually still holding the PTL, that is irrelevant)
	 */
	return atomic_read(&mm->tlb_flush_pending) > 1;
}

struct vm_fault;

struct vm_special_mapping {
	const char *name;	/* The name, e.g. "[vdso]". */

	/*
	 * If .fault is not provided, this points to a
	 * NULL-terminated array of pages that back the special mapping.
	 *
	 * This must not be NULL unless .fault is provided.
	 */
	struct page **pages;

	/*
	 * If non-NULL, then this is called to resolve page faults
	 * on the special mapping.  If used, .pages is not checked.
	 */
	vm_fault_t (*fault)(const struct vm_special_mapping *sm,
				struct vm_area_struct *vma,
				struct vm_fault *vmf);

	int (*mremap)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *new_vma);
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	TLB_REMOTE_SEND_IPI,
	NR_TLB_FLUSH_REASONS,
};

 /*
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

#endif /* _LINUX_MM_TYPES_H */
