// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2020, Jiaxun Yang <jiaxun.yang@flygoat.com>
 *  Loongson Local IO Interrupt Controller support
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/irqchip.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/io.h>
#include <linux/smp.h>
#include <linux/irqchip/chained_irq.h>

#include <boot_param.h>

#define LIOINTC_CHIP_HI_OFFSET	0x40

#ifndef CONFIG_CPU_LOONGSON2K
#define LIOINTC_INTC_CHIP_START	0x20
#define LIOINTC_CHIP_IRQ	32
#define LIOINTC_NUM_PARENT 4

#define LIOINTC_REG_INTC_STATUS	(LIOINTC_INTC_CHIP_START + 0x20)

#define LIOINTC_REG_INTC_EN_STATUS	(LIOINTC_INTC_CHIP_START + 0x04)
#define LIOINTC_REG_INTC_ENABLE	(LIOINTC_INTC_CHIP_START + 0x08)
#define LIOINTC_REG_INTC_DISABLE	(LIOINTC_INTC_CHIP_START + 0x0c)
#define LIOINTC_REG_INTC_POL	(LIOINTC_INTC_CHIP_START + 0x10)
#define LIOINTC_REG_INTC_EDGE	(LIOINTC_INTC_CHIP_START + 0x14)

#else
#define LIOINTC_INTC_CHIP_START	0x400
#define LIOINTC_CHIP_IRQ	64
#define LIOINTC_NUM_PARENT 1
#define LIOINTC_DEFAULT_CORE 0
#define LIOINTC_PARENT_INT 2


#define LIOINTC_REG_INTC_STATUS(cpu)	(0x40 + 0x100*(cpu))
#define LIOINTC_REG_INTC_STATUS_HI(cpu)	(0x48 + 0x100*(cpu))

#define LIOINTC_REG_INTC_EN_STATUS_HI	(LIOINTC_INTC_CHIP_START + 0x64)
#define LIOINTC_REG_INTC_ENABLE_HI	(LIOINTC_INTC_CHIP_START + 0x68)
#define LIOINTC_REG_INTC_DISABLE_HI	(LIOINTC_INTC_CHIP_START + 0x6c)
#define LIOINTC_REG_INTC_POL_HI	(LIOINTC_INTC_CHIP_START + 0x70)
#define LIOINTC_REG_INTC_EDGE_HI	(LIOINTC_INTC_CHIP_START + 0x74)
#define LIOINTC_REG_INTC_BOUNCE	(LIOINTC_INTC_CHIP_START + 0x38)
#define LIOINTC_REG_INTC_BOUNCE_HI	(LIOINTC_INTC_CHIP_START + 0x78)
#define LIOINTC_REG_INTC_AUTO	(LIOINTC_INTC_CHIP_START + 0x3c)
#define LIOINTC_REG_INTC_AUTO_HI	(LIOINTC_INTC_CHIP_START + 0x7c)

#define LIOINTC_REG_INTC_EN_STATUS	(LIOINTC_INTC_CHIP_START + 0x24)
#define LIOINTC_REG_INTC_ENABLE	(LIOINTC_INTC_CHIP_START + 0x28)
#define LIOINTC_REG_INTC_DISABLE	(LIOINTC_INTC_CHIP_START + 0x2c)
#define LIOINTC_REG_INTC_POL	(LIOINTC_INTC_CHIP_START + 0x30)
#define LIOINTC_REG_INTC_EDGE	(LIOINTC_INTC_CHIP_START + 0x34)
#endif

#define LIOINTC_ENTRY_AUTO(i)	(LIOINTC_INTC_CHIP_START + LIOINTC_CHIP_HI_OFFSET*(i))
#define LIOINTC_EN_STATUS_AUTO(i)	(LIOINTC_INTC_CHIP_START + 0x04 + \
			LIOINTC_CHIP_HI_OFFSET*(i))
#define LIOINTC_ENABLE_AUTO(i)	(LIOINTC_INTC_CHIP_START + 0x08 + \
			LIOINTC_CHIP_HI_OFFSET*(i))
#define LIOINTC_DISABLE_AUTO(i)	(LIOINTC_INTC_CHIP_START + 0x0c + \
			LIOINTC_CHIP_HI_OFFSET*(i))
#define LIOINTC_POL_AUTO(i)	(LIOINTC_INTC_CHIP_START + 0x10 + \
			LIOINTC_CHIP_HI_OFFSET*(i))
#define LIOINTC_EDGE_AUTO(i)	(LIOINTC_INTC_CHIP_START + 0x14 + \
			LIOINTC_CHIP_HI_OFFSET*(i))

#define LIOINTC_SHIFT_INTx	4

#define LIOINTC_ERRATA_IRQ	10

#define LIOINTC_IRQ_DISPATCH_DEFAULT		0
#define LIOINTC_IRQ_DISPATCH_BOUNCE			1
#define LIOINTC_IRQ_DISPATCH_AUTO			2
#define LIOINTC_IRQ_DISPATCH_AUTO_BOUNCE	3

struct liointc_handler_data {
	struct liointc_priv	*priv;
	u32			parent_int_map;
};

struct liointc_priv {
	struct irq_chip_generic		*gc;
	struct liointc_handler_data	handler[LIOINTC_NUM_PARENT];
	u8				map_cache[LIOINTC_CHIP_IRQ];
	bool				has_lpc_irq_errata;
};

static void liointc_chained_handle_irq(struct irq_desc *desc)
{
	struct liointc_handler_data *handler = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct irq_chip_generic *gc = handler->priv->gc;
#ifndef CONFIG_CPU_LOONGSON2K
	u32 pending;
#else
	u64 pending;
	int cpu = smp_processor_id();
#endif

	chained_irq_enter(chip, desc);

#ifndef CONFIG_CPU_LOONGSON2K
	pending = readl(gc->reg_base + LIOINTC_REG_INTC_STATUS);
#else
	pending = readl(gc->reg_base + LIOINTC_REG_INTC_STATUS(cpu));
	pending |= (u64)readl(gc->reg_base + LIOINTC_REG_INTC_STATUS_HI(cpu)) << 32;
#endif

	if (!pending) {
		/* Always blame LPC IRQ if we have that bug */
		if (handler->priv->has_lpc_irq_errata &&
			(handler->parent_int_map & ~gc->mask_cache &
			BIT(LIOINTC_ERRATA_IRQ)))
			pending = BIT(LIOINTC_ERRATA_IRQ);
		else
			spurious_interrupt();
	}

	while (pending) {
		int bit = __ffs(pending);

		generic_handle_irq(irq_find_mapping(gc->domain, bit));
		pending &= ~BIT(bit);
	}

	chained_irq_exit(chip, desc);
}

static void liointc_set_bit(struct irq_chip_generic *gc,
				unsigned int offset,
				u32 mask, bool set)
{
	if (set)
		writel(readl(gc->reg_base + offset) | mask,
				gc->reg_base + offset);
	else
		writel(readl(gc->reg_base + offset) & ~mask,
				gc->reg_base + offset);
}

static int liointc_set_type(struct irq_data *data, unsigned int type)
{
	struct irq_chip_generic *gc = irq_data_get_irq_chip_data(data);
	u32 mask = data->mask;
	unsigned long flags;
	unsigned long hwirq = data->hwirq;
	unsigned long index = hwirq/32;

#ifndef CONFIG_CPU_LOONGSON2K
	BUG_ON(hwirq >= 32);
#endif

	irq_gc_lock_irqsave(gc, flags);
	switch (type) {
	case IRQ_TYPE_LEVEL_HIGH:
		liointc_set_bit(gc, LIOINTC_EDGE_AUTO(index), mask, false);
		liointc_set_bit(gc, LIOINTC_POL_AUTO(index), mask, true);
		break;
	case IRQ_TYPE_LEVEL_LOW:
		liointc_set_bit(gc, LIOINTC_EDGE_AUTO(index), mask, false);
		liointc_set_bit(gc, LIOINTC_POL_AUTO(index), mask, false);
		break;
	case IRQ_TYPE_EDGE_RISING:
		liointc_set_bit(gc, LIOINTC_EDGE_AUTO(index), mask, true);
		liointc_set_bit(gc, LIOINTC_POL_AUTO(index), mask, true);
		break;
	case IRQ_TYPE_EDGE_FALLING:
		liointc_set_bit(gc, LIOINTC_EDGE_AUTO(index), mask, true);
		liointc_set_bit(gc, LIOINTC_POL_AUTO(index), mask, false);
		break;
	default:
		return -EINVAL;
	}
	irq_gc_unlock_irqrestore(gc, flags);

	irqd_set_trigger_type(data, type);
	return 0;
}

static int liointc_set_dispatch_mode(void *base, int mode)
{
	switch (mode) {
	case LIOINTC_IRQ_DISPATCH_BOUNCE:
		writel(0xffffffff, base + LIOINTC_REG_INTC_BOUNCE);
		writel(0xffffffff, base + LIOINTC_REG_INTC_BOUNCE_HI);
		writel(0, base + LIOINTC_REG_INTC_AUTO);
		writel(0, base + LIOINTC_REG_INTC_AUTO_HI);
		break;
	case LIOINTC_IRQ_DISPATCH_AUTO:
		writel(0, base + LIOINTC_REG_INTC_BOUNCE);
		writel(0, base + LIOINTC_REG_INTC_BOUNCE_HI);
		writel(0xffffffff, base + LIOINTC_REG_INTC_AUTO);
		writel(0xffffffff, base + LIOINTC_REG_INTC_AUTO_HI);
		break;
	case LIOINTC_IRQ_DISPATCH_AUTO_BOUNCE:
		writel(0xffffffff, base + LIOINTC_REG_INTC_BOUNCE);
		writel(0xffffffff, base + LIOINTC_REG_INTC_BOUNCE_HI);
		writel(0xffffffff, base + LIOINTC_REG_INTC_AUTO);
		writel(0xffffffff, base + LIOINTC_REG_INTC_AUTO_HI);
		break;
	default:
		/*default*/
		writel(0, base + LIOINTC_REG_INTC_BOUNCE);
		writel(0, base + LIOINTC_REG_INTC_BOUNCE_HI);
		writel(0, base + LIOINTC_REG_INTC_AUTO);
		writel(0, base + LIOINTC_REG_INTC_AUTO_HI);
		break;
	}

	return 0;
}

static void liointc_resume(struct irq_chip_generic *gc)
{
	struct liointc_priv *priv = gc->private;
	unsigned long flags;
	int i;

	irq_gc_lock_irqsave(gc, flags);
	/* Disable all at first */
	writel(0xffffffff, gc->reg_base + LIOINTC_REG_INTC_DISABLE);
#ifdef CONFIG_CPU_LOONGSON2K
	writel(0xffffffff, gc->reg_base + LIOINTC_REG_INTC_DISABLE_HI);
#endif

	/* Revert map cache */
	for (i = 0; i < LIOINTC_CHIP_IRQ; i++)
		writeb(priv->map_cache[i],
				gc->reg_base + LIOINTC_ENTRY_AUTO(i/32) + i%32);

	/* Revert mask cache */
	writel(~gc->mask_cache, gc->reg_base + LIOINTC_REG_INTC_ENABLE);
#ifdef CONFIG_CPU_LOONGSON2K
	writel(~gc->mask_cache, gc->reg_base + LIOINTC_REG_INTC_ENABLE_HI);
#endif
	irq_gc_unlock_irqrestore(gc, flags);
}

static const char * const parent_names[] = {"int0", "int1", "int2", "int3"};

int __init liointc_of_init(struct device_node *node,
				struct device_node *parent)
{
	struct irq_chip_generic *gc;
	struct irq_domain *domain;
	struct irq_chip_type *ct;
	struct liointc_priv *priv;
	void __iomem *base;
	u32 of_parent_int_map[LIOINTC_NUM_PARENT];
	int parent_irq[LIOINTC_NUM_PARENT];
	bool have_parent = FALSE;
	int dispatch_mode = 0;
	u8 core_mask = 0;
	int sz, i, err = 0;
	const char *name = NULL;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	base = of_iomap(node, 0);
	if (!base) {
		err = -ENODEV;
		goto out_free_priv;
	}

	for (i = 0; i < LIOINTC_NUM_PARENT; i++) {
		parent_irq[i] = of_irq_get_byname(node, parent_names[i]);
		if (parent_irq[i] > 0)
			have_parent = TRUE;
	}
	if (!have_parent) {
		err = -ENODEV;
		goto out_iounmap;
	}

	sz = of_property_read_variable_u32_array(node,
						"loongson,parent_int_map",
						&of_parent_int_map[0],
						LIOINTC_NUM_PARENT,
						LIOINTC_NUM_PARENT);
	if (sz < LIOINTC_NUM_PARENT) {
		pr_err("loongson-liointc: No parent_int_map\n");
		err = -ENODEV;
		goto out_iounmap;
	}

	sz = of_property_read_u32_index(node, "dispatch-mode",
						0, &dispatch_mode);
	if (sz) {
		pr_info("loongson-liointc: No dispatch-mode\n");
	}

	for (i = 0; i < LIOINTC_NUM_PARENT; i++)
		priv->handler[i].parent_int_map = of_parent_int_map[i];

	/* Setup IRQ domain */
	domain = irq_domain_add_linear(node, LIOINTC_CHIP_IRQ,
					&irq_generic_chip_ops, priv);
	if (!domain) {
		pr_err("loongson-liointc: cannot add IRQ domain\n");
		err = -EINVAL;
		goto out_iounmap;
	}

	name = of_get_property(node, "compatible", NULL);
	if (name == NULL) {
		pr_err("loongson-liointc: cannot find compatible property\n");
		err = -EINVAL;
		goto out_iounmap;
	}

	/*gc's max irq per chip is 32*/
	err = irq_alloc_domain_generic_chips(domain, 32, LIOINTC_CHIP_IRQ/32,
					name, handle_level_irq,
					IRQ_NOPROBE, 0, 0);
	if (err) {
		pr_err("loongson-liointc: unable to register IRQ domain\n");
		goto out_free_domain;
	}

	/* Disable all IRQs */
	writel(0xffffffff, base + LIOINTC_REG_INTC_DISABLE);
	/* Set to level triggered */
	writel(0x0, base + LIOINTC_REG_INTC_EDGE);

#ifdef CONFIG_CPU_LOONGSON2K
	writel(0xffffffff, base + LIOINTC_REG_INTC_DISABLE_HI);
	writel(0x0, base + LIOINTC_REG_INTC_EDGE_HI);

	liointc_set_dispatch_mode(base, dispatch_mode);
#endif

	/* Generate parent INT part of map cache */
	for (i = 0; i < LIOINTC_NUM_PARENT; i++) {
		u32 pending = priv->handler[i].parent_int_map;

		while (pending) {
			int bit = __ffs(pending);

			priv->map_cache[bit] = BIT(i) << LIOINTC_SHIFT_INTx;
			pending &= ~BIT(bit);
		}
	}

	for (i = 0; i < LIOINTC_CHIP_IRQ; i++) {
		/* Generate core part of map cache */
#ifndef CONFIG_CPU_LOONGSON2K
		priv->map_cache[i] |= BIT(loongson_sysconf.boot_cpu_id);
#else
		core_mask = 0x3;
		priv->map_cache[i] =
			1 << (LIOINTC_PARENT_INT + LIOINTC_SHIFT_INTx) |
			core_mask << LIOINTC_DEFAULT_CORE;
#endif
		writeb(priv->map_cache[i],
				base + LIOINTC_ENTRY_AUTO(i/32) + i%32);
	}

	/*gc's max irq per chip is 32*/
	for (i = 0; i < LIOINTC_CHIP_IRQ/32; i++) {
		gc = irq_get_domain_generic_chip(domain, i*32);
		gc->private = priv;
		gc->reg_base = base;
		gc->domain = domain;
		gc->resume = liointc_resume;

		ct = gc->chip_types;
		ct->regs.enable = LIOINTC_REG_INTC_ENABLE +
			i*LIOINTC_CHIP_HI_OFFSET;
		ct->regs.disable = LIOINTC_REG_INTC_DISABLE +
			i*LIOINTC_CHIP_HI_OFFSET;
		ct->chip.irq_unmask = irq_gc_unmask_enable_reg;
		ct->chip.irq_mask = irq_gc_mask_disable_reg;
		ct->chip.irq_mask_ack = irq_gc_mask_disable_reg;
		ct->chip.irq_set_type = liointc_set_type;

		gc->mask_cache = 0xffffffff;
		priv->gc = gc;
	}

	for (i = 0; i < LIOINTC_NUM_PARENT; i++) {
		if (parent_irq[i] <= 0)
			continue;

		priv->handler[i].priv = priv;
		irq_set_chained_handler_and_data(parent_irq[i],
				liointc_chained_handle_irq, &priv->handler[i]);
	}

	return 0;

out_free_domain:
	irq_domain_remove(domain);
out_iounmap:
	iounmap(base);
out_free_priv:
	kfree(priv);

	return err;
}

IRQCHIP_DECLARE(loongson_liointc_1_0,
		"loongson,liointc-1.0",
		liointc_of_init);
IRQCHIP_DECLARE(loongson_liointc_1_0a,
		"loongson,liointc-1.0a",
		liointc_of_init);
