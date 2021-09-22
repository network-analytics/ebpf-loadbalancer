
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/unistd.h>

#define USED_VLEN 1
#define MAX_TO_RECEIVE 20

#define BPF_KERNEL_PRG "unyte_reuseport_kern.o"

#ifndef MAX_BALANCER_COUNT
// Keep in sync with _kern.c
#define MAX_BALANCER_COUNT 128
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
}

/**
 * Open socket, loads eBPF program and attaches it to the opened socket.
 * int socketfd : socket file descriptor to listen to.
 * uint32_t key : index of the socket to be filled in the eBPF hash table.
 * uint32_t balancer_count : max values to be used in eBPF reuse. Should be <= MAX_BALANCER_COUNT.
 */
int unyte_attach_ebpf_to_socket(int socketfd, uint32_t key, uint32_t balancer_count)
{
  int umap_fd, size_map_fd, prog_fd;
  char filename[] = BPF_KERNEL_PRG;
  int64_t usock = socketfd;
  long err = 0;

  assert(!balancer_count || key < balancer_count);
  assert(balancer_count <= MAX_BALANCER_COUNT);
  assert(usock >= 0);

  printf("from args: Using hash bucket index %u", key);
  if (balancer_count > 0) printf(" (%u buckets in total)", balancer_count);
  puts("");

  // set log
  libbpf_set_print(libbpf_print_fn);

  // Open reuseport_udp_kern.o
  struct bpf_object_open_opts opts = {.sz = sizeof(struct bpf_object_open_opts),
                                      .pin_root_path = "/sys/fs/bpf/reuseport"};
  struct bpf_object *obj = bpf_object__open_file(filename, &opts);

  err = libbpf_get_error(obj);
  if (err) {
    perror("Failed to open BPF elf file");
    return 1;
  }

  struct bpf_map *udpmap = bpf_object__find_map_by_name(obj, "udp_balancing_targets");
  assert(udpmap);

  // Load reuseport_udp_kern.o to the kernel
  if (bpf_object__load(obj) != 0) {
    perror("Error loading BPF object into kernel");
    return 1;
  }

  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "_selector");
  if (!prog) {
    perror("Could not find BPF program in BPF object");
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  assert(prog_fd);

  umap_fd = bpf_map__fd(udpmap);
  assert(umap_fd);

  if (setsockopt(usock, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) != 0) {
    perror("Could not attach BPF prog");
    return 1;
  }

  printf("UDP sockfd: %ld\n", usock);
  if (bpf_map_update_elem(umap_fd, &key, &usock, BPF_ANY) != 0) {
    perror("Could not update reuseport array");
    return 1;
  }

  // Determine intended number of hash buckets
  // Assumption: static during lifetime of this process
  struct bpf_map *size_map = bpf_object__find_map_by_name(obj, "size");
  assert(size_map);
  size_map_fd = bpf_map__fd(size_map);
  assert(size_map_fd);

  uint32_t index = 0;
  if (balancer_count == 0) {  // no user-supplied limit
    bpf_map_lookup_elem(size_map_fd, &index, &balancer_count);
    if (balancer_count == 0) {  // BPF program hasn't run yet to initalize this
      balancer_count = MAX_BALANCER_COUNT;
      if (bpf_map_update_elem(size_map_fd, &index, &balancer_count, BPF_ANY) != 0) {
        perror("Could not update balancer count");
        return 1;
      }
    }
  } else {  // Overwrite global count with user supplied one
    if (bpf_map_update_elem(size_map_fd, &index, &balancer_count, BPF_ANY) != 0) {
      perror("Could not update balancer count");
      return 1;
    }
  }

  return 0;
}
