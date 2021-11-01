
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define USED_VLEN 1
#define MAX_TO_RECEIVE 20

#ifndef MAX_BALANCER_COUNT
// Keep in sync with _kern.c
#define MAX_BALANCER_COUNT 128
#endif

int unyte_create_udp_bound_socket(char *address, char *port, uint64_t buffer_size)
{
  assert(address != NULL);
  assert(port != NULL);
  assert(buffer_size > 0);

  struct addrinfo *addr_info;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  // Using getaddrinfo to support both IPv4 and IPv6
  int rc = getaddrinfo(address, port, &hints, &addr_info);

  if (rc != 0)
  {
    printf("getaddrinfo error: %s\n", gai_strerror(rc));
    exit(EXIT_FAILURE);
  }

  printf("Address type: %s | %d\n", (addr_info->ai_family == AF_INET) ? "IPv4" : "IPv6", ntohs(((struct sockaddr_in *)addr_info->ai_addr)->sin_port));

  // create socket on UDP protocol
  int sockfd = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);

  // handle error
  if (sockfd < 0)
  {
    perror("Cannot create socket");
    exit(EXIT_FAILURE);
  }

  // Use SO_REUSEPORT to be able to launch multiple collector on the same address
  int optval = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int)) < 0)
  {
    perror("Cannot set SO_REUSEPORT option on socket");
    exit(EXIT_FAILURE);
  }

  uint64_t receive_buf_size = buffer_size;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &receive_buf_size, sizeof(receive_buf_size)) < 0)
  {
    perror("Cannot set buffer size");
    exit(EXIT_FAILURE);
  }

  if (bind(sockfd, addr_info->ai_addr, (int)addr_info->ai_addrlen) == -1)
  {
    perror("Bind failed");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  // free addr_info after usage
  freeaddrinfo(addr_info);

  return sockfd;
}

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
//   return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
// }

int unyte_attach_ebpf_to_socket(int socketfd, uint32_t key, uint32_t balancer_count, const char pin_root_path[], const char bpf_kernel_prg_filename[])
{
  int umap_fd, size_map_fd, prog_fd;
  int64_t usock = socketfd;
  long err = 0;

  assert(!balancer_count || key < balancer_count);
  assert(balancer_count <= MAX_BALANCER_COUNT);
  assert(usock >= 0);

  printf("from args: Using hash bucket index %u", key);
  if (balancer_count > 0) printf(" (%u buckets in total)", balancer_count);
  puts("");

  // set log
  // libbpf_set_print(libbpf_print_fn);

  char pin_path[100];
  sprintf(pin_path, "/sys/fs/bpf/%s", pin_root_path);

  // Open reuseport_udp_kern.o
  struct bpf_object_open_opts opts = {.sz = sizeof(struct bpf_object_open_opts),
                                      .pin_root_path = pin_path};
  struct bpf_object *obj = bpf_object__open_file(bpf_kernel_prg_filename, &opts);

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
