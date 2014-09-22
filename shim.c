#include <linux/init.h>
#include <linux/module.h>//
#include <net/tcp.h>//
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/netfilter/nf_queue.h>

int img_init_modules(struct nf_hook_ops * nfh)
{
	nf_register_hook(nfh);
	return 0;
}
EXPORT_SYMBOL(img_init_modules);


void img_clean_modules(struct nf_hook_ops * nfh)
{
	nf_unregister_hook(nfh);
}
EXPORT_SYMBOL(img_clean_modules);

int img_iproute_harder(int clus, struct sk_buff *skb, unsigned int addr_type)
{	
	if (clus > 1) 
		return 0;
	return ip_route_me_harder(skb, addr_type);
}
EXPORT_SYMBOL(img_iproute_harder);

__sum16 img_nf_ipcs(int clus, struct sk_buff *skb, unsigned int hook, unsigned int dataoff, u_int8_t protocol)
{
	if (clus > 1)
		return nf_ip_checksum(skb,hook,0,protocol);
	return nf_ip_checksum(skb,hook,dataoff,protocol);
}
EXPORT_SYMBOL(img_nf_ipcs);

MODULE_AUTHOR("None");
MODULE_LICENSE("LGPL");
MODULE_DESCRIPTION("None");
