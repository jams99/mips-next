/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MACH_LOONGSON64_IRQ_H_
#define __ASM_MACH_LOONGSON64_IRQ_H_

#include <boot_param.h>

/* cpu core interrupt numbers */
#ifdef CONFIG_CPU_LOONGSON2K
#define MIPS_CPU_IRQ_BASE 0
#else
#define MIPS_CPU_IRQ_BASE 56
#endif

#include <asm/mach-generic/irq.h>

#endif /* __ASM_MACH_LOONGSON64_IRQ_H_ */
