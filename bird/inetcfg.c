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

#define IPV4_ADDR_BIT_LENGTH 32

#define RT_TABLE_MAIN 0

/** Main routing table */
static struct krt_proto *inetcfg_table;

/**
 * addr_compare - compares two inet addresses
 * @a: first address
 * @b: second address
 *
 * Returns 1 if equal, 0 if not equal.
 */
static int
addr_compare(const inet_addr_t *a, const inet_addr_t *b)
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

/**
 * naddrs_compare - compares two network addresses
 * @naddr_a: first network address
 * @naddr_b: second network address
 *
 * Returns 1 if equal, 0 if not equal
 */
static int
naddrs_compare(const inet_naddr_t *naddr_a, const inet_naddr_t *naddr_b)
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

/**
 * parse_link - processes link info
 * @link_info: link info
 */
static void
parse_link(inet_link_info_t *link_info)
{
  if (str_cmp(link_info->name, "net/loopback") == 0)
    return;

  struct iface f;
  memset(&f, 0, sizeof (struct iface));
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

/**
 * parse_addr - processes address info
 * @addr_info: address info
 * @inet_addr_status: address status
 */
static void
parse_addr(inet_addr_info_t *addr_info, inet_addr_status_t inet_addr_status)
{
  if (addr_info->naddr.version != ip_v4) {
    return;
  }


  struct iface *ifi = if_find_by_index(addr_info->ilink);
  if (ifi == NULL) {
    return;
  }

  struct ifa a;
  memset(&a, 0, sizeof (struct ifa));
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

/**
 * kif_do_scan - scans interfaces
 * @p: UNUSED
 */
void
kif_do_scan(struct kif_proto *p UNUSED)
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
    parse_link(&link_info);
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
      parse_addr(&addr_info, inet_addr_status);
    }
  }


  if_end_update();
}

/**
 * send_route - creates or deletes route
 * @p: route originating protocol
 * @e: routing table entry
 * @eattrs: routing table entry attributes
 * @new: 1 to create route, 0 to delete route
 */
static int
send_route(struct krt_proto *p, rte *e, struct ea_list *eattrs, int new)
{
  net *net = e->net;
  rta *a = e->attrs;

  inet_naddr_t dest;
  inet_addr_t router;

  dest.version = ip_v4;
  dest.addr = net->n.prefix.addr;
  dest.prefix = net->n.pxlen;

  router.addr = a->gw.addr;
  router.version = ip_v4;

  if (new) {
    return inetcfg_sroute_create(&dest, &router, RTPROT_BIRD);
  } else {
      inetcfg_sroute_delete(&dest, &router);
  }
  return 0;
}

/**
 * krt_replace_rte - replaces routing table entry
 * @p: originating protocol
 * @n: net
 * @new: route that will be created
 * @old: route that will be deleted
 * @eattrs: routing table entry attributes
 */
void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old,
  struct ea_list *eattrs)
{
  int err = 0;

  if (old)
    send_route(p, old, NULL, 0);

  if (new)
    err = send_route(p, new, eattrs, 1);

  if (err < 0)
    n->n.flags |= KRF_SYNC_ERROR;
  else
    n->n.flags &= ~KRF_SYNC_ERROR;
}

/**
 * parse_route - processes static route info
 * @sroute: static route
 * @inet_sroute_status: static route status
 */
static void
parse_route(inet_sroute_t *sroute)
{
  struct krt_proto *p = inetcfg_table;
  ip_addr dst;
  dst.addr = sroute->dest.addr;

  int src;
  switch (sroute->rtm_protocol) {
  case RTPROT_UNSPEC:
    return;

  case RTPROT_KERNEL:
    src = KRT_SRC_KERNEL;
    return;

  case RTPROT_BIRD:
    if (sroute->status == INET_SROUTE_STATUS_DELETED)
      return;
    src = KRT_SRC_BIRD;
    break;

  default:
    src = KRT_SRC_ALIEN;
  }
  net *net = net_get(p->p.table, dst, sroute->dest.prefix);

  rta ra = {
    .src = p->p.main_source,
    .source = RTS_INHERIT,
    .scope = SCOPE_UNIVERSE,
    .cast = RTC_UNICAST
  };

  ra.iface = NULL;
  ra.gw.addr = sroute->router.addr;
  ra.dest = RTD_ROUTER;

  rte *e = rte_get_temp(&ra);
  e->net = net;
  e->u.krt.src = src;
  e->u.krt.proto = sroute->rtm_protocol;
  e->u.krt.type = 0;

  if (sroute->status == INET_SROUTE_STATUS_ACTIVE)
    krt_got_route(p, e);
  if (sroute->status == INET_SROUTE_STATUS_DELETED)
    krt_got_route_async(p, e, 0);
}

/**
 * krt_do_scan - scans routing table
 * @p - UNUSED
 */
void
krt_do_scan(struct krt_proto *p UNUSED)
{
  inet_sroute_t *sroutes;
  size_t count;

  int rc = inetcfg_sroute_to_array(&sroutes, &count);
  if (rc != 0) {
    return;
  }

  for (size_t i = 0; i < count; i++) {
    parse_route(sroutes + i);
  }
}

/**
 * krt_capable - determine routing table entry capability
 * @e routing table entry
 *
 * Returns 1 if capable, 0 if not capable.
 */
int
krt_capable(rte *e)
{
  rta *a = e->attrs;

  if (a->cast != RTC_UNICAST)
    return 0;

  switch (a->dest) {
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


void
krt_sys_start(struct krt_proto *p)
{
  inetcfg_table = p;
}

void
krt_sys_shutdown(struct krt_proto *p UNUSED)
{
  inetcfg_table = NULL;
}

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n,
  struct krt_config *o)
{
  return n->sys.table_id == o->sys.table_id;
}

void
krt_sys_preconfig(struct config *c UNUSED) { }

void
krt_sys_postconfig(struct krt_config *x) { }

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
kif_sys_shutdown(struct kif_proto *p UNUSED) { }


