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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include "./unyte_reuseport_user.h"

#define SK_BUFFER 20971520 // 20MB of socket buffer size
#define UDP_MAX_SIZE 65535

/**
 * Creates a datagram socket with SO_REUSEPORT activated
 */
int unyte_create_socket(char *address, char *port, uint64_t buffer_size)
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

int main(int argc, char *argv[])
{
  if (argc != 5)
  {
    printf("Error: arguments not valid\n");
    printf("Usage: ./client_ebpf_user <ip> <port> <index> <loadbalance_max>\n");
    printf("Example: ./client_ebpf_user 10.0.2.15 10001 0 5\n");
    exit(1);
  }

  printf("Listening on %s:%s\n", argv[1], argv[2]);

  // Create a udp socket with default socket buffer
  int socketfd = unyte_create_socket(argv[1], argv[2], SK_BUFFER);

  // Attaching eBPF load balancer to socket
  unyte_attach_ebpf_to_socket(socketfd, atoi(argv[3]), atoi(argv[4]));

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
