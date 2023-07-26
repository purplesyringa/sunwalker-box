#include <clocksource/arm_arch_timer.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>
#include <linux/preempt.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <asm/cpucaps.h>
#include <asm/cpufeature.h>
#include <asm/debug-monitors.h>
#include <asm/esr.h>
#include <asm/exception.h>
#include <asm/insn-def.h>
#include <asm/sysreg.h>
#include <asm/traps.h>

#ifndef ESR_ELx_SYS64_ISS_SYS_CNTVCTSS
#define ESR_ELx_SYS64_ISS_SYS_CNTVCTSS  (ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 6, 14, 0) | \
                                         ESR_ELx_SYS64_ISS_DIR_READ)
#endif

#ifndef ESR_ELx_CP15_64_ISS_SYS_CNTVCTSS
#define ESR_ELx_CP15_64_ISS_SYS_CNTVCTSS (ESR_ELx_CP15_64_ISS_SYS_VAL(9, 14) | \
                                         ESR_ELx_CP15_64_ISS_DIR_READ)
#endif

DEFINE_PER_CPU(pid_t, controller_pid);
DEFINE_PER_CPU(u64, controller_start_time);
DEFINE_PER_CPU(u64, cntvct_offset);
DEFINE_PER_CPU(struct task_struct *, next_current);

static void (*sw_arm64_skip_faulting_instruction)(struct pt_regs *regs, unsigned long size);

static bool is_offset_enabled(struct task_struct *task)
{
	pid_t cur_controller_pid;
	u64 cur_controller_start_time;
	unsigned int ns_level;
	struct task_struct* proc;
	bool found = false;

	cur_controller_pid = this_cpu_read(controller_pid);
	if (cur_controller_pid == 0)
		return false;

	cur_controller_start_time = this_cpu_read(controller_start_time);

	rcu_read_lock();
	if (pid_alive(task)) {
		ns_level = task_pid(task)->level;
		for (
			proc = rcu_dereference(task->real_parent);
			pid_alive(proc) && task_pid(proc)->level == ns_level;
			proc = rcu_dereference(proc->real_parent)
		) {
			if (proc->tgid == cur_controller_pid && proc->start_time == cur_controller_start_time) {
				found = true;
				break;
			}
			if (proc == &init_task)
				break;
		}
	}
	rcu_read_unlock();

	return found;
}

// Disable ARM64_WORKAROUND_1418040 if on a sunwalker core
static int this_cpu_has_cap_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int n = regs->regs[0];
	if (n == ARM64_WORKAROUND_1418040) {
		struct task_struct *next = this_cpu_read(next_current);
		if (next && is_offset_enabled(next))
			regs->regs[0] = -1;
	}
	return 0;
}

static int __switch_to_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *next = (void *)regs->regs[1];
	this_cpu_write(next_current, next);
	if (is_offset_enabled(next))
		sysreg_clear_set(cntkctl_el1, ARCH_TIMER_USR_VCT_ACCESS_EN, 0);
	else
		sysreg_clear_set(cntkctl_el1, 0, ARCH_TIMER_USR_VCT_ACCESS_EN);
	return 0;
}

static u64 read_counter_with_offset(void) {
	return arch_timer_read_counter() + this_cpu_read(cntvct_offset);
}

// Emulate cntvct if on a sunwalker core
static struct pt_regs fake_regs = {
	.pstate = PSR_MODE_EL1t
};

static int do_el0_sys_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int esr;
	struct pt_regs *userland_regs;

	if (!is_offset_enabled(current))
		return 0;

	esr = regs->regs[0];
	userland_regs = (void *)regs->regs[1];

	if (
		(esr & ESR_ELx_SYS64_ISS_SYS_OP_MASK) == ESR_ELx_SYS64_ISS_SYS_CNTVCT
		|| (esr & ESR_ELx_SYS64_ISS_SYS_OP_MASK) == ESR_ELx_SYS64_ISS_SYS_CNTVCTSS
	) {
		int rt = ESR_ELx_SYS64_ISS_RT(esr);
		pt_regs_write_reg(userland_regs, rt, read_counter_with_offset());
		sw_arm64_skip_faulting_instruction(userland_regs, AARCH64_INSN_SIZE);
		regs->regs[1] = (u64)&fake_regs;
	}

	return 0;
}

#ifdef CONFIG_COMPAT
static int do_el0_cp15_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int esr;
	struct pt_regs *userland_regs;

	if (!is_offset_enabled(current))
		return 0;

	esr = regs->regs[0];
	userland_regs = (void *)regs->regs[1];

	if (
		ESR_ELx_EC(esr) == ESR_ELx_EC_CP15_64
		&& (
			(esr & ESR_ELx_CP15_64_ISS_SYS_MASK) == ESR_ELx_CP15_64_ISS_SYS_CNTVCT
			|| (esr & ESR_ELx_CP15_64_ISS_SYS_MASK) == ESR_ELx_CP15_64_ISS_SYS_CNTVCTSS
		)
	) {
		int rt = (esr & ESR_ELx_CP15_64_ISS_RT_MASK) >> ESR_ELx_CP15_64_ISS_RT_SHIFT;
		int rt2 = (esr & ESR_ELx_CP15_64_ISS_RT2_MASK) >> ESR_ELx_CP15_64_ISS_RT2_SHIFT;
		u64 val = read_counter_with_offset();
		pt_regs_write_reg(userland_regs, rt, lower_32_bits(val));
		pt_regs_write_reg(userland_regs, rt2, upper_32_bits(val));
		sw_arm64_skip_faulting_instruction(userland_regs, 4);
		regs->regs[1] = (u64)&fake_regs;
	}

	return 0;
}
#endif

static struct kprobe arm64_skip_faulting_instruction_kp = {
	.symbol_name = "arm64_skip_faulting_instruction"
};
static struct kprobe this_cpu_has_cap_kp = {
	.symbol_name = "this_cpu_has_cap",
	.pre_handler = this_cpu_has_cap_pre_handler
};
static struct kprobe __switch_to_kp = {
	.symbol_name = "__switch_to",
	.pre_handler = __switch_to_pre_handler
};
static struct kprobe do_el0_sys_kp = {
	.symbol_name = "do_el0_sys",
	.pre_handler = do_el0_sys_pre_handler
};
#ifdef CONFIG_COMPAT
static struct kprobe do_el0_cp15_kp = {
	.symbol_name = "do_el0_cp15",
	.pre_handler = do_el0_cp15_pre_handler
};
#endif

static struct kprobe* kps[] = {
	&arm64_skip_faulting_instruction_kp,
	&this_cpu_has_cap_kp,
	&__switch_to_kp,
	&do_el0_sys_kp
#ifdef CONFIG_COMPAT
	, &do_el0_cp15_kp
#endif
};

static ssize_t timing_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(
		buf,
		"%d %llu %llu %lld\n",
		this_cpu_read(controller_pid),
		this_cpu_read(controller_start_time),
		this_cpu_read(cntvct_offset),
		read_sysreg(cntkctl_el1)
	);
}

static ssize_t timing_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	pid_t pid;
	u64 offset;
	if (sscanf(buf, "%d%llu", &pid, &offset) != 2)
		return -EINVAL;
	if (pid != 0) {
		struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (!task)
			return -EINVAL;
		this_cpu_write(controller_start_time, task->start_time);
	}
	this_cpu_write(controller_pid, pid);
	this_cpu_write(cntvct_offset, offset);
	return count;
}

static struct kobject *sys_kernel_sunwalker;
static struct kobj_attribute timing_attribute = __ATTR(timing, 0660, timing_show, timing_store);

int init_module(void)
{
	sys_kernel_sunwalker = kobject_create_and_add("sunwalker", kernel_kobj);
	if (!sys_kernel_sunwalker) {
		pr_err("sunwalker: Failed to register /sys/kernel/sunwalker");
		return -ENOMEM;
	}

	if (sysfs_create_file(sys_kernel_sunwalker, &timing_attribute.attr) < 0) {
		kobject_put(sys_kernel_sunwalker);
		pr_err("sunwalker: Failed to register /sys/kernel/sunwalker/timing");
		return -ENOMEM;
	}

	if (register_kprobes(kps, sizeof(kps) / sizeof(*kps)) < 0) {
		kobject_put(sys_kernel_sunwalker);
		pr_err("sunwalker: Failed to register kprobe for this_cpu_has_cap");
		return -ENOMEM;
	}

	sw_arm64_skip_faulting_instruction = (void *)kps[0]->addr;

	return 0;
}

void cleanup_module(void)
{
	kobject_put(sys_kernel_sunwalker);
	unregister_kprobes(kps, sizeof(kps) / sizeof(*kps));
}

MODULE_LICENSE("Dual MIT/GPL");
