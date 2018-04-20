/*
 *	BIRD Internet Routing Daemon -- Linux Multicasting and Network Includes
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2018 Stanislav Galfy <sgalfy@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#ifndef HAVE_STRUCT_IP_MREQN
struct ip_mreqn
{
  struct in_addr imr_multiaddr;
  struct in_addr imr_address;
  int		 imr_ifindex;
};
#endif

#ifndef IP_MINTTL
#define IP_MINTTL 21
#endif

#ifndef IPV6_TCLASS
#define IPV6_TCLASS 67
#endif

#ifndef IPV6_MINHOPCOUNT
#define IPV6_MINHOPCOUNT 73
#endif

#define SA_LEN(x) sizeof(sockaddr)

static inline int
sk_setup_multicast4(sock *s)
{
  struct ip_mreqn mr = { .imr_ifindex = s->iface->index };
  
  if (setsockopt(s->fd, SOL_IP, IP_MULTICAST_IF, &mr, sizeof(mr)) < 0)
    ERR("IP_MULTICAST_IF");
  
  return 0;
}

static inline int
sk_join_group4(sock *s, ip_addr maddr)
{
  return 0;
}

static inline int
sk_leave_group4(sock *s, ip_addr maddr)
{
  return 0;
}


/*
 *	Linux IPv4 packet control messages
 */

/* Mostly similar to standardized IPv6 code */

#define CMSG4_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in_pktinfo))
#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline int
sk_request_cmsg4_pktinfo(sock *s)
{
  return 0;
}

static inline int
sk_request_cmsg4_ttl(sock *s)
{

  return 0;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_PKTINFO)
  {
    struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cm);
    s->laddr = ipa_from_in4(pi->ipi_addr);
    s->lifindex = pi->ipi_ifindex;
  }
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_TTL)
    s->rcv_ttl = * (int *) CMSG_DATA(cm);
}

static inline void
sk_prepare_cmsgs4(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  struct cmsghdr *cm;
  struct in_pktinfo *pi;
  int controllen = 0;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = SOL_IP;
  cm->cmsg_type = IP_PKTINFO;
  cm->cmsg_len = CMSG_LEN(sizeof(*pi));
  controllen += CMSG_SPACE(sizeof(*pi));

  pi = (struct in_pktinfo *) CMSG_DATA(cm);
  pi->ipi_ifindex = s->iface ? s->iface->index : 0;
  pi->ipi_spec_dst = ipa_to_in4(s->saddr);
  pi->ipi_addr = ipa_to_in4(IPA_NONE);

  msg->msg_controllen = controllen;
}

int
sk_set_md5_auth(sock *s, ip_addr a, struct iface *ifa, char *passwd)
{
  return 0;
}

static inline int
sk_set_min_ttl4(sock *s, int ttl)
{
  return 0;
}

static inline int
sk_set_min_ttl6(sock *s, int ttl)
{
  return 0;
}

static inline int
sk_disable_mtu_disc4(sock *s)
{
  return 0;
}

static inline int
sk_disable_mtu_disc6(sock *s)
{
  return 0;
}

int sk_priority_control = 7;

static inline int
sk_set_priority(sock *s, int prio)
{
  return 0;
}


