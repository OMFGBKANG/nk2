/*
<<<<<<< HEAD
 * TTL modification target for IP tables
 * (C) 2000,2005 by Harald Welte <laforge@netfilter.org>
 *
 * Hop Limit modification target for ip6tables
 * Maciej Soltysiak <solt@dns.toxicfilms.tv>
=======
 * IP tables module for matching the value of the TTL
 * (C) 2000,2001 by Harald Welte <laforge@netfilter.org>
 *
 * Hop Limit matching module
 * (C) 2001-2002 Maciej Soltysiak <solt@dns.toxicfilms.tv>
>>>>>>> 9b6a062... Fix compiling and changes for smartassV2 governor.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
<<<<<<< HEAD
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_TTL.h>
#include <linux/netfilter_ipv6/ip6t_HL.h>

MODULE_AUTHOR("Harald Welte <laforge@netfilter.org>");
MODULE_AUTHOR("Maciej Soltysiak <solt@dns.toxicfilms.tv>");
MODULE_DESCRIPTION("Xtables: Hoplimit/TTL Limit field modification target");
MODULE_LICENSE("GPL");

static unsigned int
ttl_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct ipt_TTL_info *info = par->targinfo;
	int new_ttl;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	iph = ip_hdr(skb);

	switch (info->mode) {
		case IPT_TTL_SET:
			new_ttl = info->ttl;
			break;
		case IPT_TTL_INC:
			new_ttl = iph->ttl + info->ttl;
			if (new_ttl > 255)
				new_ttl = 255;
			break;
		case IPT_TTL_DEC:
			new_ttl = iph->ttl - info->ttl;
			if (new_ttl < 0)
				new_ttl = 0;
			break;
		default:
			new_ttl = iph->ttl;
			break;
	}

	if (new_ttl != iph->ttl) {
		csum_replace2(&iph->check, htons(iph->ttl << 8),
					   htons(new_ttl << 8));
		iph->ttl = new_ttl;
	}

	return XT_CONTINUE;
}

static unsigned int
hl_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6h;
	const struct ip6t_HL_info *info = par->targinfo;
	int new_hl;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	ip6h = ipv6_hdr(skb);

	switch (info->mode) {
		case IP6T_HL_SET:
			new_hl = info->hop_limit;
			break;
		case IP6T_HL_INC:
			new_hl = ip6h->hop_limit + info->hop_limit;
			if (new_hl > 255)
				new_hl = 255;
			break;
		case IP6T_HL_DEC:
			new_hl = ip6h->hop_limit - info->hop_limit;
			if (new_hl < 0)
				new_hl = 0;
			break;
		default:
			new_hl = ip6h->hop_limit;
			break;
	}

	ip6h->hop_limit = new_hl;

	return XT_CONTINUE;
}

static int ttl_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_TTL_info *info = par->targinfo;

	if (info->mode > IPT_TTL_MAXMODE) {
		pr_info("TTL: invalid or unknown mode %u\n", info->mode);
		return -EINVAL;
	}
	if (info->mode != IPT_TTL_SET && info->ttl == 0)
		return -EINVAL;
	return 0;
}

static int hl_tg6_check(const struct xt_tgchk_param *par)
{
	const struct ip6t_HL_info *info = par->targinfo;

	if (info->mode > IP6T_HL_MAXMODE) {
		pr_info("invalid or unknown mode %u\n", info->mode);
		return -EINVAL;
	}
	if (info->mode != IP6T_HL_SET && info->hop_limit == 0) {
		pr_info("increment/decrement does not "
			"make sense with value 0\n");
		return -EINVAL;
	}
	return 0;
}

static struct xt_target hl_tg_reg[] __read_mostly = {
	{
		.name       = "TTL",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = ttl_tg,
		.targetsize = sizeof(struct ipt_TTL_info),
		.table      = "mangle",
		.checkentry = ttl_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "HL",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = hl_tg6,
		.targetsize = sizeof(struct ip6t_HL_info),
		.table      = "mangle",
		.checkentry = hl_tg6_check,
=======

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_ttl.h>
#include <linux/netfilter_ipv6/ip6t_hl.h>

MODULE_AUTHOR("Maciej Soltysiak <solt@dns.toxicfilms.tv>");
MODULE_DESCRIPTION("Xtables: Hoplimit/TTL field match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ttl");
MODULE_ALIAS("ip6t_hl");

static bool ttl_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct ipt_ttl_info *info = par->matchinfo;
	const u8 ttl = ip_hdr(skb)->ttl;

	switch (info->mode) {
		case IPT_TTL_EQ:
			return ttl == info->ttl;
		case IPT_TTL_NE:
			return ttl != info->ttl;
		case IPT_TTL_LT:
			return ttl < info->ttl;
		case IPT_TTL_GT:
			return ttl > info->ttl;
	}

	return false;
}

static bool hl_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct ip6t_hl_info *info = par->matchinfo;
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	switch (info->mode) {
		case IP6T_HL_EQ:
			return ip6h->hop_limit == info->hop_limit;
		case IP6T_HL_NE:
			return ip6h->hop_limit != info->hop_limit;
		case IP6T_HL_LT:
			return ip6h->hop_limit < info->hop_limit;
		case IP6T_HL_GT:
			return ip6h->hop_limit > info->hop_limit;
	}

	return false;
}

static struct xt_match hl_mt_reg[] __read_mostly = {
	{
		.name       = "ttl",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.match      = ttl_mt,
		.matchsize  = sizeof(struct ipt_ttl_info),
		.me         = THIS_MODULE,
	},
	{
		.name       = "hl",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.match      = hl_mt6,
		.matchsize  = sizeof(struct ip6t_hl_info),
>>>>>>> 9b6a062... Fix compiling and changes for smartassV2 governor.
		.me         = THIS_MODULE,
	},
};

<<<<<<< HEAD
static int __init hl_tg_init(void)
{
	return xt_register_targets(hl_tg_reg, ARRAY_SIZE(hl_tg_reg));
}

static void __exit hl_tg_exit(void)
{
	xt_unregister_targets(hl_tg_reg, ARRAY_SIZE(hl_tg_reg));
}

module_init(hl_tg_init);
module_exit(hl_tg_exit);
MODULE_ALIAS("ipt_TTL");
MODULE_ALIAS("ip6t_HL");
=======
static int __init hl_mt_init(void)
{
	return xt_register_matches(hl_mt_reg, ARRAY_SIZE(hl_mt_reg));
}

static void __exit hl_mt_exit(void)
{
	xt_unregister_matches(hl_mt_reg, ARRAY_SIZE(hl_mt_reg));
}

module_init(hl_mt_init);
module_exit(hl_mt_exit);
>>>>>>> 9b6a062... Fix compiling and changes for smartassV2 governor.
