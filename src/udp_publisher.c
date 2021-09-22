/**
 * Publisher of udp packets to test main.c
 * This code allows sending "Hello World !" messages to a connected IP/port.
 * 
 * Usage: ./udp_publisher <ip> <port> <nb_message_to_send>
 * 
 * Example for sending 10 message:        ./udp_publisher 10.0.2.15 10001 10
 * Example for sending infinite messages: ./udp_publisher 10.0.2.15 10001 0
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define SEND_SK_BUFFER 20971520 // 20MB of socket buffer size
#define UDP_MAX_SIZE 65535

int create_udp_socket(char *address, char *port, uint64_t buffer_size)
{
  struct addrinfo *addr_info;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  int rc = getaddrinfo(address, port, &hints, &addr_info);

  if (rc != 0)
  {
    printf("getaddrinfo error: %s\n", gai_strerror(rc));
    exit(EXIT_FAILURE);
  }

  int sockfd = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);

  if (sockfd < 0)
  {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)))
  {
    perror("Set socket buffer size");
    exit(EXIT_FAILURE);
  }

  // connect socket to destination address
  if (connect(sockfd, addr_info->ai_addr, (int)addr_info->ai_addrlen) == -1)
  {
    perror("Connect failed");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  // free addr_info after usage
  freeaddrinfo(addr_info);

  return sockfd;
}

int main(int argc, char *argv[])
{
  if (argc != 4)
  {
    printf("Error: arguments not valid\n");
    printf("Usage: ./udp_publisher <ip> <port> <nb_messages>\n");
    printf("Example: ./udp_publisher 10.0.2.15 10001 10\n");
    exit(1);
  }

  printf("Sending on %s:%s\n", argv[1], argv[2]);

  int socket_fd = create_udp_socket(argv[1], argv[2], SEND_SK_BUFFER);

  int messages_to_send = atoi(argv[3]);
  bool infinite = false;
  if (messages_to_send == 0)
    infinite = true;

  char buf[100];
  int buf_len = strlen(buf);
  int count = 0;
  while (1)
  {
    if (!infinite)
    {
      messages_to_send--;
      if (messages_to_send < 0)
        break;
    }

    sprintf(buf, "Hello World %d!", count);
    buf_len = strlen(buf);
    count++;

    if (send(socket_fd, buf, buf_len, 0) < 0)
      fprintf(stderr, "Error sending response\n");
    sleep(1);
  }
  return 0;
}
