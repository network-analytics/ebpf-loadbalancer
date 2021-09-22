#ifndef UNYTE_REUSEPORT_USER_H
#define UNYTE_REUSEPORT_USER_H

#include <stdint.h>

int unyte_attach_ebpf_to_socket(int socketfd, uint32_t key, uint32_t balancer_count);

#endif
