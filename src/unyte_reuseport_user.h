#ifndef UNYTE_REUSEPORT_USER_H
#define UNYTE_REUSEPORT_USER_H

#include <stdint.h>

/**
 * Creates a datagram socket with SO_REUSEPORT activated and already bound to addres/port
 */
int unyte_create_udp_bound_socket(char *address, char *port, uint64_t buffer_size);

/**
 * Open socket, loads eBPF program and attaches it to the opened socket.
 * int socketfd : socket file descriptor to listen to.
 * uint32_t key : index of the socket to be filled in the eBPF hash table.
 * uint32_t balancer_count : max values to be used in eBPF reuse. Should be <= MAX_BALANCER_COUNT.
 * const char pin_root_path[] : pin root path of eBPFFS (/sys/fs/bpf/<pin_root_path>)
 * const char bpf_kernel_prg_filename[] : BPF kernel .o program
 */
int unyte_attach_ebpf_to_socket(int socketfd, uint32_t key, uint32_t balancer_count, const char pin_root_path[], const char bpf_kernel_prg[]);

#endif
