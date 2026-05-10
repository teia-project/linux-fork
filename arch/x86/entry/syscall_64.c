// SPDX-License-Identifier: GPL-2.0-only
/* 64-bit system call dispatch */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/bpf-cgroup.h>
#include <linux/syscalls.h>
#include <linux/entry-common.h>
#include <linux/nospec.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/gfp.h>
#include <asm/syscall.h>

#define __SYSCALL(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#define __SYSCALL_NORETURN(nr, sym) extern long __noreturn __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#ifdef CONFIG_X86_X32_ABI
#include <asm/syscalls_x32.h>
#endif
#undef  __SYSCALL

#undef  __SYSCALL_NORETURN
#define __SYSCALL_NORETURN __SYSCALL

/*
 * The sys_call_table[] is no longer used for system calls, but
 * kernel/trace/trace_syscalls.c still wants to know the system
 * call address.
 */
#define __SYSCALL(nr, sym) __x64_##sym,
const sys_call_ptr_t sys_call_table[] = {
#include <asm/syscalls_64.h>
};
#undef  __SYSCALL

#define __SYSCALL(nr, sym) case nr: return __x64_##sym(regs);
long x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_64.h>
	default: return __x64_sys_ni_syscall(regs);
	}
}

#ifdef CONFIG_X86_X32_ABI
long x32_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_x32.h>
	default: return __x64_sys_ni_syscall(regs);
	}
}
#endif

// /// eBPF programs can access through kernel virtual memory
// /// syscalls take userland pointers
// /// thus we do a read-only mapping to the page in userland
// /// and a read/write mapping in kernel space
// /// and tada! we avoid tocttou
// /// Yes, unsigned long is used as a pointer in the kernel -- forget provenance!
// /// Since we're mmaping something, we might OOM -- so we just kill the calling
// /// process
// static int mmap_eps_scratch(unsigned long *kptr_out, struct page **page, unsigned long *uptr_out)
// {       
//         // todo(oli): leaks on some ooms
//         *page = alloc_page(GFP_KERNEL);
//         if (*page == NULL) return -1; // oom
//         void *kptr = page_address(*page); 
        
//         // this is just mmap()
//         unsigned long uptr = vm_mmap(
//                 NULL, 
//                 0,
//                 PAGE_SIZE,
//                 PROT_NONE,
//                 MAP_PRIVATE | MAP_ANONYMOUS,
//                 0
//         ); 
//         if (IS_ERR_VALUE(uptr)) return -1; // oom
        
//         struct mm_struct *mm = current->mm;
//         if (mm == NULL) {
//                 return -1;
//         }
//         mmap_write_lock(mm);
//         struct vm_area_struct *vma = find_vma(mm, uptr);
//         // we have to check this > addr thing technically since someone could've
//         // munmapped in the meantime
//         if (vma == NULL || vma->vm_start > uptr) {
//                 // oom
//                 mmap_write_unlock(mm);
//                 return -1; 
//         }
//         // we need to turn off this 'maywrite' thing so the user can't call
//         // mprotect
//         vm_flags_clear(vma, VM_MAYWRITE);
//         if (vm_insert_page(vma, uptr, *page) < 0) {
//                 // oom
//                 mmap_write_unlock(mm);
//                 return -1; 
//         }
//         mmap_write_unlock(mm);

//         *kptr_out = (unsigned long)kptr;
//         *uptr_out = uptr;

//         return 0;
// }

// static void munmap_eps_scratch(unsigned long kptr, struct page *page, unsigned long uptr)
// {
//         put_page(page); 
//         struct mm_struct *mm = current->mm;
//         mmap_write_lock(mm);
//         do_munmap(mm, uptr, PAGE_SIZE, NULL);
//         mmap_write_unlock(mm);
// }

// static __always_inline bool do_syscall_x64(struct pt_regs *regs, int nr)
// {
// 	/*
// 	 * Convert negative numbers to very high and thus out of range
// 	 * numbers for comparisons.
// 	 */
// 	unsigned int unr = nr;
        
//         // EPS entry
//         struct page *page; 
//         unsigned long kscratch, uscratch;
//         __u8 resolve_ptr_regs = 0; 
//         if (cgroup_bpf_enabled(CGROUP_SYSCALL_ENTER)) {	               
//                 if (mmap_eps_scratch(&kscratch, &page, &uscratch) < 0) {
//                         do_exit(SIGKILL);
//                 } 
//                 __cgroup_bpf_run_filter_syscall_enter(regs, &nr, &resolve_ptr_regs, kscratch, uscratch);  
//         }

//         bool ret = false;
// 	if (likely(unr < NR_syscalls)) {
// 		unr = array_index_nospec(unr, NR_syscalls);
// 		regs->ax = x64_sys_call(regs, unr);
// 		ret = true;
// 	}

//         // munmap the scratch
//         if (kscratch) {
//                 munmap_eps_scratch(kscratch, page, uscratch);
//         }

// 	return ret;
// }

// cache for which syscalls have active eps hooks, eps programmers can disable
// // these to speed things up, 511th bit is reserved 
// static __u64 eps_hooks[6] = {
//         (1ul << 39) | (1ul << 55), // 39 (pid), 55 (getsockopt)
//         (1ul << 33),               // 96 (timeofday)
//         0,                         
//         (1ul << 1),                // 257 (openat)
//         0,
//         0
// };

// static bool eps_hook_is_active(unsigned int unr)
// {
//         unsigned int idx = unr >> 6; // word index
//         unsigned int off = unr & 63; // bit offset
//         __u64 w = __atomic_load_n(&eps_hooks[idx], __ATOMIC_RELAXED);
//         return (w >> off) & 1;
// }

static __always_inline bool do_syscall_x64(struct pt_regs *regs, int nr)
{
	/*
	 * Convert negative numbers to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int unr = nr;

        // // fast path using cached bit
        // if (!eps_hook_is_active(nr)) {
        //         if (likely(unr < NR_syscalls)) {
        //                 unr = array_index_nospec(unr, NR_syscalls);
        //                 regs->ax = x64_sys_call(regs, unr);
        //                 return true;
        //         }
        //         return false;
        // }

        bool ret = false;
        // bool repeat = true;
        // while (repeat) {
                int bpf_ret = 0;
                __u8 resolve_ptr_regs = 0; 
                char scratch[4096];
                
                if (cgroup_bpf_enabled(CGROUP_SYSCALL_ENTER)) {
                        current->kuser_space_start = (unsigned long)&scratch[0];
                        current->kuser_space_end = current->kuser_space_start + 4096;
                        bpf_ret = __cgroup_bpf_run_filter_syscall_enter(regs, &nr, &resolve_ptr_regs);  
                }

                // // this means return early 
                // if ((bpf_ret & 2) != 0) {
                //         return false;
                // } 
                
                if (likely(unr < NR_syscalls)) {
                        unr = array_index_nospec(unr, NR_syscalls);
                        regs->ax = x64_sys_call(regs, unr);
                        ret = true;
                }
        
                current->kuser_space_start = 0;
                current->kuser_space_end = 0;
                if (cgroup_bpf_enabled(CGROUP_SYSCALL_EXIT)) {
                        __cgroup_bpf_run_filter_syscall_exit(regs, &nr, &resolve_ptr_regs);
                }

        // } 

	return ret;
}


static __always_inline bool do_syscall_x32(struct pt_regs *regs, int nr)
{
	/*
	 * Adjust the starting offset of the table, and convert numbers
	 * < __X32_SYSCALL_BIT to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int xnr = nr - __X32_SYSCALL_BIT;

	if (IS_ENABLED(CONFIG_X86_X32_ABI) && likely(xnr < X32_NR_syscalls)) {
		xnr = array_index_nospec(xnr, X32_NR_syscalls);
		regs->ax = x32_sys_call(regs, xnr);
		return true;
	}
	return false;
}

/* Returns true to return using SYSRET, or false to use IRET */
__visible noinstr bool do_syscall_64(struct pt_regs *regs, int nr)
{
	add_random_kstack_offset();
	nr = syscall_enter_from_user_mode(regs, nr);

	instrumentation_begin();

	if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
		/* Invalid system call, but still a system call. */
		regs->ax = __x64_sys_ni_syscall(regs);
	}

	instrumentation_end();
	syscall_exit_to_user_mode(regs);

	/*
	 * Check that the register state is valid for using SYSRET to exit
	 * to userspace.  Otherwise use the slower but fully capable IRET
	 * exit path.
	 */

	/* XEN PV guests always use the IRET path */
	if (cpu_feature_enabled(X86_FEATURE_XENPV))
		return false;

	/* SYSRET requires RCX == RIP and R11 == EFLAGS */
	if (unlikely(regs->cx != regs->ip || regs->r11 != regs->flags))
		return false;

	/* CS and SS must match the values set in MSR_STAR */
	if (unlikely(regs->cs != __USER_CS || regs->ss != __USER_DS))
		return false;

	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the user take over
	 * the kernel, since userspace controls RSP.
	 *
	 * TASK_SIZE_MAX covers all user-accessible addresses other than
	 * the deprecated vsyscall page.
	 */
	if (unlikely(regs->ip >= TASK_SIZE_MAX))
		return false;

	/*
	 * SYSRET cannot restore RF.  It can restore TF, but unlike IRET,
	 * restoring TF results in a trap from userspace immediately after
	 * SYSRET.
	 */
	if (unlikely(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)))
		return false;

	/* Use SYSRET to exit to userspace */
	return true;
}
