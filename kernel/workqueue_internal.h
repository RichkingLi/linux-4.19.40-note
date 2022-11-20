/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/workqueue_internal.h
 *
 * Workqueue internal header file.  Only to be included by workqueue and
 * core kernel subsystems.
 */
#ifndef _KERNEL_WORKQUEUE_INTERNAL_H
#define _KERNEL_WORKQUEUE_INTERNAL_H

#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

struct worker_pool;

/*
 * The poor guys doing the actual heavy lifting.  All on-duty workers are
 * either serving the manager role, on idle list or on busy hash.  For
 * details on the locking annotation (L, I, X...), refer to workqueue.c.
 *
 * Only to be used in workqueue and async.
 */
struct worker {
	/* on idle list while idle, on busy hash table while busy */
	union {
		struct list_head	entry;//工人空闲的时候挂在空闲链表
		struct hlist_node	hentry;//工人忙的时候呀挂在hash链表
	};

	struct work_struct	*current_work;//工人当前进行的任务
	work_func_t		current_func;//工人当前任务的函数
	struct pool_workqueue	*current_pwq;//工人所在的pwq
	struct list_head	scheduled;//工人预计安排的任务

	/* 64 bytes boundary on 64bit, 32 on 32bit */

	struct task_struct	*task;//记录工人的进程task_struct
	struct worker_pool	*pool;//工人所在的工作池
						/* L: for rescuers */
	struct list_head	node;//工人所在的内存节点
						/* A: runs through worker->node */

	unsigned long		last_active;	/* L: last active timestamp */
	unsigned int		flags;//属性
	int			id;//工人的ID

	/*
	 * Opaque string set with work_set_desc().  Printed out with task
	 * dump for debugging - WARN, BUG, panic or sysrq.
	 */
	char			desc[WORKER_DESC_LEN];//工人的描述字符串

	/* used only by rescuers to point to the target workqueue */
	struct workqueue_struct	*rescue_wq;//救援的工作队列
};

/**
 * current_wq_worker - return struct worker if %current is a workqueue worker
 */
static inline struct worker *current_wq_worker(void)
{
	if (in_task() && (current->flags & PF_WQ_WORKER))
		return kthread_data(current);
	return NULL;
}

/*
 * Scheduler hooks for concurrency managed workqueue.  Only to be used from
 * sched/core.c and workqueue.c.
 */
void wq_worker_waking_up(struct task_struct *task, int cpu);
struct task_struct *wq_worker_sleeping(struct task_struct *task);

#endif /* _KERNEL_WORKQUEUE_INTERNAL_H */
