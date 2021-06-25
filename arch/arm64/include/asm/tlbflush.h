/*
 * Based on arch/arm/include/asm/tlbflush.h
 *
 * Copyright (C) 1999-2003 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_TLBFLUSH_H
#define __ASM_TLBFLUSH_H

#ifndef __ASSEMBLY__

#include <linux/sched.h>
#include <asm/cputype.h>
#include <asm/mmu.h>

/*
 * Raw TLBI operations.
 *
 * Where necessary, use the __tlbi() macro to avoid asm()
 * boilerplate. Drivers and most kernel code should use the TLB
 * management routines in preference to the macro below.
 *
 * The macro can be used as __tlbi(op) or __tlbi(op, arg), depending
 * on whether a particular TLBI operation takes an argument or
 * not. The macros handles invoking the asm with or without the
 * register argument as appropriate.
 */
#define __TLBI_0(op, arg) asm ("tlbi " #op "\n"				       \
		   ALTERNATIVE("nop\n			nop",		       \
			       "dsb ish\n		tlbi " #op,	       \
			       ARM64_WORKAROUND_REPEAT_TLBI,		       \
			       CONFIG_QCOM_FALKOR_ERRATUM_1009)		       \
			    : : )

#define __TLBI_1(op, arg) asm ("tlbi " #op ", %0\n"			       \
		   ALTERNATIVE("nop\n			nop",		       \
			       "dsb ish\n		tlbi " #op ", %0",     \
			       ARM64_WORKAROUND_REPEAT_TLBI,		       \
			       CONFIG_QCOM_FALKOR_ERRATUM_1009)		       \
			    : : "r" (arg))

#define __TLBI_N(op, arg, n, ...) __TLBI_##n(op, arg)

#define __tlbi(op, ...)		__TLBI_N(op, ##__VA_ARGS__, 1, 0)

#define __tlbi_user(op, arg) do {						\
	if (arm64_kernel_unmapped_at_el0())					\
		__tlbi(op, (arg) | USER_ASID_FLAG);				\
} while (0)

/* This macro creates a properly formatted VA operand for the TLBI */
#define __TLBI_VADDR(addr, asid)				\
	({							\
		unsigned long __ta = (addr) >> 12;		\
		__ta &= GENMASK_ULL(43, 0);			\
		__ta |= (unsigned long)(asid) << 48;		\
		__ta;						\
	})

/*
 *	TLB Management
 *	==============
 *
 *	The TLB specific code is expected to perform whatever tests it needs
 *	to determine if it should invalidate the TLB for each call.  Start
 *	addresses are inclusive and end addresses are exclusive; it is safe to
 *	round these addresses down.
 *
 *	flush_tlb_all()
 *
 *		Invalidate the entire TLB.
 *
 *	flush_tlb_mm(mm)
 *
 *		Invalidate all TLB entries in a particular address space.
 *		- mm	- mm_struct describing address space
 *
 *	flush_tlb_range(mm,start,end)
 *
 *		Invalidate a range of TLB entries in the specified address
 *		space.
 *		- mm	- mm_struct describing address space
 *		- start - start address (may not be aligned)
 *		- end	- end address (exclusive, may not be aligned)
 *
 *	flush_tlb_page(vaddr,vma)
 *
 *		Invalidate the specified page in the specified address range.
 *		- vaddr - virtual address (may not be aligned)
 *		- vma	- vma_struct describing address range
 *
 *	flush_kern_tlb_page(kaddr)
 *
 *		Invalidate the TLB entry for the specified page.  The address
 *		will be in the kernels virtual memory space.  Current uses
 *		only require the D-TLB to be invalidated.
 *		- kaddr - Kernel virtual memory address
 */
//使当前cpu的所有的tlb表失效
static inline void local_flush_tlb_all(void)
{
	//nshst和ishst区别：nsh是非共享，ish是多核共享
	dsb(nshst);//数据同步屏障，确保屏障前的当前cpu的存储指令执行完毕
	
	/*vmalle1：
	vm：需要匹配VMID
	all：所有ASID
	e1：异常级别（有三个异常级别e1 e2 e3）
	is：表示多核共享
	*/
	__tlbi(vmalle1);//使当前核上匹配VMID的，异常级别1的所有TLB失效
	dsb(nsh);//确保之前的tlb失效指令执行完毕
	isb();//指令同步屏障，冲刷处理器流水线，重新读取屏障后的所有指令
}

//使所有的tlb表失效
static inline void flush_tlb_all(void)
{
	//nshst和ishst区别：nsh是非共享，ish是多核共享
	dsb(ishst);//数据同步屏障，确保屏障前的所有cpu的存储指令执行完毕
	/*vmalle1：
	vm：需要匹配VMID
	all：所有ASID
	e1：异常级别（有三个异常级别e1 e2 e3）
	is：缺少is表示单核非共享
	*/
	__tlbi(vmalle1is);//使所有核上匹配VMID的，异常级别1的所有TLB失效
	dsb(ish);//确保之前的tlb失效指令执行完毕
	isb();//指令同步屏障，冲刷处理器流水线，重新读取屏障后的所有指令
}

//使指定用户地址空间的所有的tlb表失效，参数mm是进程的内存描述符
static inline void flush_tlb_mm(struct mm_struct *mm)
{
	unsigned long asid = __TLBI_VADDR(0, ASID(mm));

	dsb(ishst);
	__tlbi(aside1is, asid);
	__tlbi_user(aside1is, asid);
	dsb(ish);
}

//使指定用户地址空间的指定页面的tlb表失效
static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long uaddr)
{
	unsigned long addr = __TLBI_VADDR(uaddr, ASID(vma->vm_mm));

	dsb(ishst);
	__tlbi(vale1is, addr);
	__tlbi_user(vale1is, addr);
	dsb(ish);
}

/*
 * This is meant to avoid soft lock-ups on large TLB flushing ranges and not
 * necessarily a performance improvement.
 */
#define MAX_TLB_RANGE	(1024UL << PAGE_SHIFT)

static inline void __flush_tlb_range(struct vm_area_struct *vma,
				     unsigned long start, unsigned long end,
				     bool last_level)
{
	unsigned long asid = ASID(vma->vm_mm);
	unsigned long addr;

	if ((end - start) > MAX_TLB_RANGE) {
		flush_tlb_mm(vma->vm_mm);
		return;
	}

	start = __TLBI_VADDR(start, asid);
	end = __TLBI_VADDR(end, asid);

	dsb(ishst);
	for (addr = start; addr < end; addr += 1 << (PAGE_SHIFT - 12)) {
		if (last_level) {
			__tlbi(vale1is, addr);
			__tlbi_user(vale1is, addr);
		} else {
			__tlbi(vae1is, addr);
			__tlbi_user(vae1is, addr);
		}
	}
	dsb(ish);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	__flush_tlb_range(vma, start, end, false);
}

static inline void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	unsigned long addr;

	if ((end - start) > MAX_TLB_RANGE) {
		flush_tlb_all();
		return;
	}

	start = __TLBI_VADDR(start, 0);
	end = __TLBI_VADDR(end, 0);

	dsb(ishst);
	for (addr = start; addr < end; addr += 1 << (PAGE_SHIFT - 12))
		__tlbi(vaae1is, addr);
	dsb(ish);
	isb();
}

/*
 * Used to invalidate the TLB (walk caches) corresponding to intermediate page
 * table levels (pgd/pud/pmd).
 */
static inline void __flush_tlb_pgtable(struct mm_struct *mm,
				       unsigned long uaddr)
{
	unsigned long addr = __TLBI_VADDR(uaddr, ASID(mm));

	__tlbi(vae1is, addr);
	__tlbi_user(vae1is, addr);
	dsb(ish);
}

static inline void __flush_tlb_kernel_pgtable(unsigned long kaddr)
{
	unsigned long addr = __TLBI_VADDR(kaddr, 0);

	__tlbi(vaae1is, addr);
	dsb(ish);
}
#endif

#endif
