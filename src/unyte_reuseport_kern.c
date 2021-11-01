// clang-format off
#include "vmlinux.h"
// clang-format on
#include <bpf/bpf_helpers.h>

#ifndef MAX_BALANCER_COUNT
// Keep in sync with _user.c
#define MAX_BALANCER_COUNT 128
#endif

// bpf_printk argument limits
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define LOC __FILE__ ":" STRINGIFY(__LINE__) ": "

const u32 zero = 0;  // array access index
const u32 balancer_max = MAX_BALANCER_COUNT;

// MAPS

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} nonce SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} size SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, MAX_BALANCER_COUNT);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, MAX_BALANCER_COUNT);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_balancing_targets SEC(".maps");

// HASHING

#define __jhash_final(a, b, c) \
  {                            \
    c ^= b;                    \
    c -= rol32(b, 14);         \
    a ^= c;                    \
    a -= rol32(c, 11);         \
    b ^= a;                    \
    b -= rol32(a, 25);         \
    c ^= b;                    \
    c -= rol32(b, 16);         \
    a ^= c;                    \
    a -= rol32(c, 4);          \
    b ^= a;                    \
    b -= rol32(a, 14);         \
    c ^= b;                    \
    c -= rol32(b, 24);         \
  }
#define JHASH_INITVAL 0xdeadbeef

static inline __u32 rol32(__u32 word, unsigned int shift) { return (word << (shift & 31)) | (word >> ((-shift) & 31)); }

static inline u32 hash(u32 ip) {
  u32 a, b, c, initval, *n;

  // Initialize nonce if not done already
  n = bpf_map_lookup_elem(&nonce, &zero);
  if (n == 0) {
    // Cannot happen as BPF_MAP_TYPE_ARRAY always resolves
    return SK_DROP;
  }

  if (*n == 0) {
    // TODO: Handle bpf_get_prandom_u32() == 0
    *n = bpf_get_prandom_u32();

#ifdef _LOG_DEBUG
    bpf_printk(LOC "Updating nonce to %x\n", *n);
#endif
  }

  initval = *n;

  initval += JHASH_INITVAL + (3 << 2);
  a = ip + initval;
  b = initval;
  c = initval;

  __jhash_final(a, b, c);
  return c;
}

// CORE LOGIC

SEC("sk_reuseport/selector")
enum sk_action _selector(struct sk_reuseport_md *reuse) {
  enum sk_action action;
  struct iphdr ip;
  u32 key;

  void *targets;

  switch (reuse->ip_protocol) {
    case IPPROTO_TCP:
      targets = &tcp_balancing_targets;
      break;
    case IPPROTO_UDP:
      targets = &udp_balancing_targets;
      break;
    default:
#ifdef _LOG_DEBUG
      bpf_printk(LOC "Unsupported IPPROTO=%d\n", reuse->ip_protocol);
#endif
      return SK_DROP;
  }

  bpf_skb_load_bytes_relative(reuse, 0, &ip, sizeof(struct iphdr), (u32)BPF_HDR_START_NET);

  const u32 *balancer_count = bpf_map_lookup_elem(&size, &zero);
  if (!balancer_count || *balancer_count == 0) {  // uninitialized by userspace
    balancer_count = &balancer_max;
    bpf_map_update_elem(&size, &zero, balancer_count, BPF_ANY);
  }

#ifdef _LOG_DEBUG
  bpf_printk(LOC "Balancing across %d hash buckets\n", *balancer_count);
#endif

  // hash on the IP only
  key = hash(__builtin_bswap32(ip.saddr)) % *balancer_count;

#ifdef _LOG_DEBUG
  bpf_printk(LOC "src: %x, dest: %x, key: %d\n", __builtin_bswap32(ip.saddr), __builtin_bswap32(ip.daddr), key);
#endif

  // side-effect sets dst socket if found
  if (bpf_sk_select_reuseport(reuse, targets, &key, 0) == 0) {
    action = SK_PASS;
#ifdef _LOG_DEBUG
    bpf_printk(LOC "=> action: pass\n\n");
#endif
  } else {
    action = SK_DROP;
#ifdef _LOG_DEBUG
    bpf_printk(LOC "=> action: drop\n\n");
#endif
  }

  return action;
}

char _license[] SEC("license") = "GPL";
