#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <inet/inetcfg.h>

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/alloca.h"
#include "lib/timer.h"
#include "lib/unix.h"
#include "lib/krt.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "conf/conf.h"

/** Kernel table  index */
#define RT_TABLE_MAIN 254

#define IPV4_ADDR_BIT_LENGTH 32

/** Routing tables map */
static struct krt_proto *nl_table_map[NL_NUM_TABLES];

/** Compares two inet addresses.
 * 
 * @param a - first address
 * @param b - second address
 * @return - 1 if equal, 0 if not equal
 */
static int addr_compare(const inet_addr_t *a, const inet_addr_t *b)
{
	if (a->version != b->version)
		return 0;

	switch (a->version) {
	case ip_v4:
		return (a->addr == b->addr);
	case ip_v6:
		return (memcmp(a->addr6, b->addr6, 16) == 0);
	default:
		return 0;
	}
}

/** Compares two network addresses.
 * 
 * @param naddr_a - first network address
 * @param naddr_b - second network address
 * @return - 1 if equal, 0 if not equal
 */
static int naddrs_compare (const inet_naddr_t *naddr_a, const inet_naddr_t *naddr_b) 
{              
        if (naddr_a->prefix != naddr_b->prefix)
                return 0;

        if (naddr_a->version != naddr_b->version)
                return 0;

	switch (naddr_a->version) {
	case ip_v4:
		return (naddr_a->addr == naddr_b->addr);
	case ip_v6:
		return (memcmp(naddr_a->addr6, naddr_b->addr6, 16) == 0);
	default:
		return 0;
	}
}

/** Processes link info.
 * 
 * @param link_info - link info
 */
static void nl_parse_link(inet_link_info_t *link_info) 
{    
        if (str_cmp(link_info->name, "net/loopback") == 0)
                return;

        struct iface f;
	memset(&f, 0, sizeof(struct iface));
        struct iface *ifi;

        strncpy(f.name, link_info->name, 16);
        loc_service_get_id(f.name, &f.index, 0);

        f.mtu = link_info->def_mtu;
        f.flags = 0;
        f.flags |= IF_ADMIN_UP;
        f.flags |= IF_LINK_UP;
        f.flags |= IF_MULTIACCESS;
        f.flags |= IF_BROADCAST;
        f.flags |= IF_MULTICAST;      

        ifi = if_update(&f);    
}

/** Processes address info.
 * 
 * @param addr_info - address info
 * @param inet_addr_status - address status
 */
static void nl_parse_addr(inet_addr_info_t *addr_info,
        inet_addr_status_t inet_addr_status) 
{
        if (addr_info->naddr.version != ip_v4) {
                return;
        }


        struct iface *ifi = if_find_by_index(addr_info->ilink);
        if (ifi == NULL) {
                return;
        }

        struct ifa a;
	memset(&a, 0, sizeof(struct ifa));
        a.iface = ifi;
        a.ip.addr = addr_info->naddr.addr;
        a.flags = 0;
        a.pxlen = addr_info->naddr.prefix;
        uint32_t shift = IPV4_ADDR_BIT_LENGTH - a.pxlen;
        a.prefix.addr = (addr_info->naddr.addr >> shift) << shift;
        a.brd.addr = addr_info->naddr.addr;
        int mask = 1;
        for (int i = 0; i < shift; i++) {
            a.brd.addr |= mask;
            mask *= 2;
        }

        a.opposite = ipa_build4(0, 0, 0, 0);
        a.scope = ipa_classify(a.ip) & IADDR_SCOPE_MASK;

        if (inet_addr_status == INET_ADDR_STATUS_ACTIVE)
                ifa_update(&a);           
        if (inet_addr_status == INET_ADDR_STATUS_DELETED)
                ifa_delete(&a);
}

/** Scans interfaces.
 * 
 * @param p - UNUSED
 */
void kif_do_scan(struct kif_proto *p UNUSED)
{
        if_start_update();

        sysarg_t *link_list;
        inet_link_info_t link_info;
        size_t link_count;

        size_t i;
        int rc;

        rc = inetcfg_get_link_list(&link_list, &link_count);
        if (rc != EOK) {       
                if_end_update();
                return;
        }

        for (i = 0; i < link_count; i++) {
                rc = inetcfg_link_get(link_list[i], &link_info);
                if (rc != EOK)
                        continue;
                nl_parse_link(&link_info);
        }

        sysarg_t *addr_list;
        inet_addr_info_t addr_info;
        size_t addr_count;

        size_t j;

        for (int i = 0; i <= 1; i++) {
                inet_addr_status_t inet_addr_status;
                if (i == 0)
                    inet_addr_status = INET_ADDR_STATUS_ACTIVE;
                if (i == 1)
                    inet_addr_status = INET_ADDR_STATUS_DELETED;

                rc = inetcfg_get_addr_list(&addr_list, &addr_count,
                    inet_addr_status);
		
                if (rc != EOK) {       
                  if_end_update();
                  return;
                }

                for (j = 0; j < addr_count; j++) {
                        rc = inetcfg_addr_get(addr_list[j], &addr_info,
                            inet_addr_status);
                        if (rc != EOK)
                                continue;
                        nl_parse_addr(&addr_info, inet_addr_status);
                }
        }


        if_end_update();
}

/** Creates or deletes route.
 * 
 * @param p - route originating protocol
 * @param e - routing table entry
 * @param eattrs - routing table entry attributes
 * @param new - 1 to create route, 0 to delete route
 * @return 
 */
static int nl_send_route(struct krt_proto *p, rte *e, struct ea_list *eattrs,
        int new)
{   
        net *net = e->net;
        rta *a = e->attrs;

        inet_naddr_t dest;
        inet_addr_t router;
        sysarg_t sroute_id;

        dest.version = ip_v4;
        dest.addr = net->n.prefix.addr;
        dest.prefix = net->n.pxlen;

        router.addr = a->gw.addr;
        router.version = ip_v4;

        if (new) {
                sysarg_t *sroute_list;
                inet_sroute_info_t srinfo;
                size_t count;
                inetcfg_get_sroute_list(&sroute_list, &count,
                    INET_SROUTE_STATUS_ACTIVE);
                /*
		for (size_t i = 0; i < count; i++) {
                    inetcfg_sroute_get(sroute_list[i], &srinfo,
                        INET_SROUTE_STATUS_ACTIVE);
                    if (naddrs_compare(&srinfo.dest, &dest))
                            return -1;
                }
		*/
                inetcfg_sroute_create("BIRD_ROUTE", &dest, &router, 
                    RTPROT_BIRD, &sroute_id);
                return 0;
        }
        else {
                sysarg_t *sroute_list;
                inet_sroute_info_t srinfo;
                size_t count;
                inetcfg_get_sroute_list(&sroute_list, &count,
                    INET_SROUTE_STATUS_ACTIVE);
                for (size_t i = 0; i < count; i++) {
                        inetcfg_sroute_get(sroute_list[i], &srinfo,
                            INET_SROUTE_STATUS_ACTIVE);
                        if (!naddrs_compare(&srinfo.dest, &dest))
                                continue;
                        if (!addr_compare(&srinfo.router, &router))
                                continue;
                        inetcfg_sroute_delete(sroute_list[i]);
                        return 0;
                }
        }
        return 0;
}

/** Replaces routing table entry.
 * 
 * @param p - originating protocol
 * @param n - net
 * @param new - route that will be created
 * @param old - route that will be deleted
 * @param eattrs - routing table entry attributes
 */
void krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old,
    struct ea_list *eattrs)
{
        int err = 0;

        if (old)
                nl_send_route(p, old, NULL, 0);

        if (new)
                err = nl_send_route(p, new, eattrs, 1);

        if (err < 0)
                n->n.flags |= KRF_SYNC_ERROR;
        else
                n->n.flags &= ~KRF_SYNC_ERROR;
}

/** Processes static route info.
 * 
 * @param srinfo - static route info
 * @param inet_sroute_status - static route status
 */
static void nl_parse_route(inet_sroute_info_t *srinfo,
    inet_sroute_status_t inet_sroute_status) 
{
        struct krt_proto *p = nl_table_map[RT_TABLE_MAIN];
        ip_addr dst;
        dst.addr = srinfo->dest.addr;

        int src;
        switch (srinfo->rtm_protocol) {
        case RTPROT_UNSPEC:
                return;

        case RTPROT_KERNEL:
                src = KRT_SRC_KERNEL;
                return;

        case RTPROT_BIRD:
                if (inet_sroute_status == INET_SROUTE_STATUS_DELETED)
                        return;
                src = KRT_SRC_BIRD;
                break;

        default:
                src = KRT_SRC_ALIEN;
        }
        net *net = net_get(p->p.table, dst, srinfo->dest.prefix);

        rta ra = {
                .src= p->p.main_source,
                .source = RTS_INHERIT,
                .scope = SCOPE_UNIVERSE,
                .cast = RTC_UNICAST
        };

        ra.iface = NULL;
        ra.gw.addr = srinfo->router.addr;
        ra.dest = RTD_ROUTER;

        rte *e = rte_get_temp(&ra);
        e->net = net;
        e->u.krt.src = src;
        e->u.krt.proto = srinfo->rtm_protocol;
        e->u.krt.type = 0;

        if (inet_sroute_status == INET_SROUTE_STATUS_ACTIVE)
                krt_got_route(p, e);
        if (inet_sroute_status == INET_SROUTE_STATUS_DELETED)
                krt_got_route_async(p, e, 0);    
}

/** Scans routing table.
 * 
 * @param p - UNUSED
 */
void krt_do_scan(struct krt_proto *p UNUSED)
{ 
        sysarg_t *sroute_list;
        inet_sroute_info_t srinfo;
        size_t count;
	
        for (int i = 0; i <= 1; i++) {
                inet_sroute_status_t inet_sroute_status;
                if (i == 0)
                        inet_sroute_status = INET_SROUTE_STATUS_ACTIVE;
                if (i == 1)
                        inet_sroute_status = INET_SROUTE_STATUS_DELETED;


                int rc = inetcfg_get_sroute_list(&sroute_list, &count,
                    inet_sroute_status);
                if (rc != EOK)
                        continue;
                for (size_t i = 0; i < count; i++) {
                    inetcfg_sroute_get(sroute_list[i], &srinfo,
                        inet_sroute_status);
                    if (rc != EOK)
                            continue;
                    nl_parse_route(&srinfo, inet_sroute_status);
                }
        }
}

/** Determine routing table entry capability.
 * 
 * @param e - routing table entry
 * @return - 1 if capable, 0 if not capable
 */
int krt_capable(rte *e)
{
        rta *a = e->attrs;

        if (a->cast != RTC_UNICAST)
                return 0;

        switch (a->dest)
        {
        case RTD_ROUTER:
        case RTD_DEVICE:
                if (a->iface == NULL)
                        return 0;
        case RTD_BLACKHOLE:
        case RTD_UNREACHABLE:
        case RTD_PROHIBIT:
        case RTD_MULTIPATH:
                break;
        default:
                return 0;
        }
        return 1;
}

/*
 *	Interface to the UNIX krt module
 */


void krt_sys_start(struct krt_proto *p)
{
        nl_table_map[KRT_CF->sys.table_id] = p;
}

void
krt_sys_shutdown(struct krt_proto *p UNUSED)
{
        nl_table_map[KRT_CF->sys.table_id] = NULL;
}

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
        return n->sys.table_id == o->sys.table_id;
}

void
krt_sys_preconfig(struct config *c UNUSED)
{
}

void
krt_sys_postconfig(struct krt_config *x)
{
}

void
krt_sys_init_config(struct krt_config *cf)
{
        cf->sys.table_id = RT_TABLE_MAIN;
}

void
krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{
        d->sys.table_id = s->sys.table_id;
}

void
kif_sys_start(struct kif_proto *p UNUSED)
{
        inetcfg_init();
}

void
kif_sys_shutdown(struct kif_proto *p UNUSED)
{
}


