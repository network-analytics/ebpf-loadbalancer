/**
 * Example of client using a eBPF loadbalancer.
 * This allows multiple client instances listening on the same IP/port and receiving consistent data
 * (all packets from one src IP will always go on the same collector)
 *
 * Usage: ./main <ip> <port> <index> <balancer_max>
 *
 * Example: launching 3 instances on the same ip port. The index is the index on the map to put the socket
 * and the balancer_max is how many max instances are in use.
 *
 *    ./main 192.168.1.17 10001 0 3
 *    ./main 192.168.1.17 10001 1 3
 *    ./main 192.168.1.17 10001 2 3
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "./unyte_reuseport_user.h"

// if installed in machine
// #include <unyte-reuseport-loadbalancer/unyte_reuseport_user.h>

#define SK_BUFFER 20971520 // 20MB of socket buffer size
#define UDP_MAX_SIZE 65535

int main(int argc, char *argv[])
{
  if (argc != 5)
  {
    printf("Error: arguments not valid\n");
    printf("Usage: ./main <ip> <port> <index> <loadbalance_max>\n");
    printf("Example: ./main 10.0.2.15 10001 0 5\n");
    exit(1);
  }

  printf("Listening on %s:%s\n", argv[1], argv[2]);

  // Create a udp socket with default socket buffer
  int socketfd = unyte_create_udp_bound_socket(argv[1], argv[2], SK_BUFFER);

  // Attaching eBPF load balancer to socket
  int ret_attach = unyte_attach_ebpf_to_socket(socketfd, atoi(argv[3]), atoi(argv[4]), "unyte_reuseport", "unyte_reuseport_kern.o");

  if (ret_attach != 0)
    exit(1);

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len = sizeof(struct sockaddr_storage);
  ssize_t nread;
  char buf[UDP_MAX_SIZE];

  while (1)
  {
    nread = recvfrom(socketfd, buf, UDP_MAX_SIZE, 0,
                     (struct sockaddr *)&peer_addr, &peer_addr_len);

    if (nread == -1)
      continue; // Ignore failed request

    char ip_src_canonical[100];
    printf("****** Message ******\n");
    if (peer_addr.ss_family == AF_INET)
    {
      printf("Received %ld bytes from %s:%u\n", (long)nread,
             inet_ntop(peer_addr.ss_family, &((struct sockaddr_in *)&peer_addr)->sin_addr.s_addr, ip_src_canonical, sizeof ip_src_canonical),
             ntohs(((struct sockaddr_in *)&peer_addr)->sin_port));
    }
    else
    {
      printf("Received %ld bytes from %s:%u\n", (long)nread,
             inet_ntop(peer_addr.ss_family, &((struct sockaddr_in *)&peer_addr)->sin_addr.s_addr, ip_src_canonical, sizeof ip_src_canonical),
             ntohs(((struct sockaddr_in6 *)&peer_addr)->sin6_port));
    }
    printf("Buffer: %.*s\n", (int)nread, buf);
    printf("**** End Message ****\n\n");
  }

  return 0;
}
