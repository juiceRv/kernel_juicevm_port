/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Lennox Wu <lennox.wu@sunplusct.com>
 *  Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 */


#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/uaccess.h>

#include <asm/pgalloc.h>
#include <asm/ptrace.h>

/*
 * This routine handles page faults.  It determines the address and the
 * problem, and then passes it off to one of the appropriate routines.
 */
asmlinkage void do_page_fault(struct pt_regs *regs)
{
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	struct task_struct *tsk;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long addr, cause;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	int code = SEGV_MAPERR;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	vm_fault_t fault;

	cause = regs->scause;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	addr = regs->sbadaddr;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	tsk = current;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d current:%lx",__FILE__,__FUNCTION__,__LINE__,user_mode(regs),current);
	mm = tsk->mm;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	/*
	 * Fault-in kernel-space virtual memory on-demand.
	 * The 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 */
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (unlikely((addr >= VMALLOC_START) && (addr <= VMALLOC_END)))
		goto vmalloc_fault;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	/* Enable interrupts if they were enabled in the parent context. */
	if (likely(regs->sstatus & SR_SPIE))
		local_irq_enable();

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d  faulthandler_disabled():%d mm:%lx",__FILE__,__FUNCTION__,__LINE__,user_mode(regs),faulthandler_disabled(),mm);
	/*
	 * If we're in an interrupt, have no user context, or are running
	 * in an atomic region, then we must not take the fault.
	 */
	if (unlikely(faulthandler_disabled() || !mm))
		goto no_context;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
retry:
	down_read(&mm->mmap_sem);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	vma = find_vma(mm, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (unlikely(!vma))
		goto bad_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (likely(vma->vm_start <= addr))
		goto good_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN)))
		goto bad_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (unlikely(expand_stack(vma, addr)))
		goto bad_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it.
	 */
good_area:
	code = SEGV_ACCERR;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	switch (cause) {
	case EXC_INST_PAGE_FAULT:
		if (!(vma->vm_flags & VM_EXEC))
			goto bad_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		break;
	case EXC_LOAD_PAGE_FAULT:
		if (!(vma->vm_flags & VM_READ))
			goto bad_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		break;
	case EXC_STORE_PAGE_FAULT:
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		flags |= FAULT_FLAG_WRITE;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		break;
	default:
		panic("%s: unhandled cause %lu", __func__, cause);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	}

	/*
	 * If for any reason at all we could not handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	fault = handle_mm_fault(vma, addr, flags);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	/*
	 * If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_sem because it
	 * would already be released in __lock_page_or_retry in mm/filemap.c.
	 */
	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(tsk))
		return;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (unlikely(fault & VM_FAULT_ERROR)) {
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		BUG();
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	}

	/*
	 * Major/minor page fault accounting is only done on the
	 * initial attempt. If we go through a retry, it is extremely
	 * likely that the page will be found in page cache at that point.
	 */
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (fault & VM_FAULT_MAJOR) {
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
			tsk->maj_flt++;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				      1, regs, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		} else {
			tsk->min_flt++;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				      1, regs, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		}
		if (fault & VM_FAULT_RETRY) {
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
			/*
			 * Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk
			 * of starvation.
			 */
			flags &= ~(FAULT_FLAG_ALLOW_RETRY);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
			flags |= FAULT_FLAG_TRIED;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

			/*
			 * No need to up_read(&mm->mmap_sem) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */
			goto retry;
		}
	}

	up_read(&mm->mmap_sem);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	return;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	/*
	 * Something tried to access memory that isn't in our memory map.
	 * Fix it, but check if it's kernel or user first.
	 */
bad_area:
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	up_read(&mm->mmap_sem);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs)) {
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		do_trap(regs, SIGSEGV, code, addr, tsk);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		return;
	}

no_context:
	pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs))
		return;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	bust_spinlocks(1);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	pr_alert("Unable to handle kernel %s at virtual address " REG_FMT "\n",
		(addr < PAGE_SIZE) ? "NULL pointer dereference" :
		"paging request", addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	die(regs, "Oops");
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	do_exit(SIGKILL);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

	/*
	 * We ran out of memory, call the OOM killer, and return the userspace
	 * (which will retry the fault, or kill us if we got oom-killed).
	 */
out_of_memory:
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	up_read(&mm->mmap_sem);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	if (!user_mode(regs))
		goto no_context;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	pagefault_out_of_memory();
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	return;

do_sigbus:
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	up_read(&mm->mmap_sem);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	/* Kernel mode? Handle exceptions or die */
	if (!user_mode(regs))
		goto no_context;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	do_trap(regs, SIGBUS, BUS_ADRERR, addr, tsk);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
	return;

vmalloc_fault:
	{
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		pgd_t *pgd, *pgd_k;
		pud_t *pud, *pud_k;
		p4d_t *p4d, *p4d_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;
		int index;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (user_mode(regs))
			goto bad_area;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk->active_mm->pgd" here.
		 * We might be inside an interrupt in the middle
		 * of a task switch.
		 *
		 * Note: Use the old spbtr name instead of using the current
		 * satp name to support binutils 2.29 which doesn't know about
		 * the privileged ISA 1.10 yet.
		 */
		index = pgd_index(addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		pgd = (pgd_t *)pfn_to_virt(csr_read(sptbr)) + index;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		pgd_k = init_mm.pgd + index;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

		if (!pgd_present(*pgd_k))
			goto no_context;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		set_pgd(pgd, *pgd_k);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

		p4d = p4d_offset(pgd, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		p4d_k = p4d_offset(pgd_k, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (!p4d_present(*p4d_k))
			goto no_context;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		pud = pud_offset(p4d, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		pud_k = pud_offset(p4d_k, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (!pud_present(*pud_k))
			goto no_context;

	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		/*
		 * Since the vmalloc area is global, it is unnecessary
		 * to copy individual PTEs
		 */
		pmd = pmd_offset(pud, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		pmd_k = pmd_offset(pud_k, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (!pmd_present(*pmd_k))
			goto no_context;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		set_pmd(pmd, *pmd_k);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));

		/*
		 * Make sure the actual PTE exists as well to
		 * catch kernel vmalloc-area accesses to non-mapped
		 * addresses. If we don't do this, this will just
		 * silently loop forever.
		 */
		pte_k = pte_offset_kernel(pmd_k, addr);
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		if (!pte_present(*pte_k))
			goto no_context;
	// pr_notice("f:%s func:%s line:%d user_mode(regs) %d",__FILE__,__FUNCTION__,__LINE__,user_mode(regs));
		return;
	}
}
