/**
 * Example of client using a eBPF loadbalancer.
 * This allows multiple client instances listening on the same IP/port and receiving consistent data
 * (all packets from one src IP will always go on the same collector)
 *
 * Usage: ./client_ebpf_user <ip> <port> <index> <balancer_max>
 *
 * Example: launching 3 instances on the same ip port. The index is the index on the map to put the socket
 * and the balancer_max is how many max instances are in use.
 *
 *    ./client_ebpf_user 192.168.1.17 10001 0 3
 *    ./client_ebpf_user 192.168.1.17 10001 1 3
 *    ./client_ebpf_user 192.168.1.17 10001 2 3
 */

#include <stdlib.h>
#include <stdio.h>

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
  // int socketfd = unyte_udp_create_socket(argv[1], argv[2], DEFAULT_SK_BUFF_SIZE);

  // attach_ebpf_to_socket(socketfd, atoi(argv[3]), atoi(argv[4]));

//   // Initialize collector options
//   unyte_udp_options_t options = {0};
//   options.recvmmsg_vlen = USED_VLEN;
//   options.socket_fd = socketfd;
//   printf("Listening on socket %d\n", options.socket_fd);

//   /* Initialize collector */
//   unyte_udp_collector_t *collector = unyte_udp_start_collector(&options);
//   int recv_count = 0;
//   int max = MAX_TO_RECEIVE;

//   while (recv_count < max)
//   {
//     /* Read queue */
//     void *seg_pointer = unyte_udp_queue_read(collector->queue);
//     if (seg_pointer == NULL)
//     {
//       printf("seg_pointer null\n");
//       fflush(stdout);
//     }
//     unyte_seg_met_t *seg = (unyte_seg_met_t *)seg_pointer;

//     // printf("unyte_udp_get_version: %u\n", unyte_udp_get_version(seg));
//     // printf("unyte_udp_get_space: %u\n", unyte_udp_get_space(seg));
//     // printf("unyte_udp_get_encoding_type: %u\n", unyte_udp_get_encoding_type(seg));
//     // printf("unyte_udp_get_header_length: %u\n", unyte_udp_get_header_length(seg));
//     // printf("unyte_udp_get_message_length: %u\n", unyte_udp_get_message_length(seg));
//     // printf("unyte_udp_get_generator_id: %u\n", unyte_udp_get_generator_id(seg));
//     // printf("unyte_udp_get_message_id: %u\n", unyte_udp_get_message_id(seg));
//     // printf("unyte_udp_get_src[family]: %u\n", unyte_udp_get_src(seg)->ss_family);
//     // printf("unyte_udp_get_dest_addr[family]: %u\n", unyte_udp_get_dest_addr(seg)->ss_family);
//     char ip_canonical[100];
//     if (unyte_udp_get_src(seg)->ss_family == AF_INET) {
//       printf("src IPv4: %s\n", inet_ntop(unyte_udp_get_src(seg)->ss_family, &((struct sockaddr_in*)unyte_udp_get_src(seg))->sin_addr.s_addr, ip_canonical, sizeof ip_canonical));
//       printf("src port: %u\n", ntohs(((struct sockaddr_in*)unyte_udp_get_src(seg))->sin_port));
//     } else {
//       printf("src IPv6: %s\n", inet_ntop(unyte_udp_get_src(seg)->ss_family, &((struct sockaddr_in6*)unyte_udp_get_src(seg))->sin6_addr.s6_addr, ip_canonical, sizeof ip_canonical));
//       printf("src port: %u\n", ntohs(((struct sockaddr_in6*)unyte_udp_get_src(seg))->sin6_port));
//     }
//     char ip_dest_canonical[100];
//     if (unyte_udp_get_src(seg)->ss_family == AF_INET) {
//       printf("dest IPv4: %s\n", inet_ntop(unyte_udp_get_dest_addr(seg)->ss_family, &((struct sockaddr_in*)unyte_udp_get_dest_addr(seg))->sin_addr.s_addr, ip_dest_canonical, sizeof ip_dest_canonical));
//       printf("dest port: %u\n", ntohs(((struct sockaddr_in*)unyte_udp_get_dest_addr(seg))->sin_port));
//     } else {
//       printf("dest IPv6: %s\n", inet_ntop(unyte_udp_get_dest_addr(seg)->ss_family, &((struct sockaddr_in6*)unyte_udp_get_dest_addr(seg))->sin6_addr.s6_addr, ip_dest_canonical, sizeof ip_dest_canonical));
//       printf("dest port: %u\n", ntohs(((struct sockaddr_in6*)unyte_udp_get_dest_addr(seg))->sin6_port));
//     }
//     // printf("unyte_udp_get_payload: %s\n", unyte_udp_get_payload(seg));
//     // printf("unyte_udp_get_payload_length: %u\n", unyte_udp_get_payload_length(seg));

//     /* Processing sample */
//     recv_count++;
//     print_udp_notif_header(seg->header, stdout);
//     // hexdump(seg->payload, seg->header->message_length - seg->header->header_length);

//     fflush(stdout);

//     /* Struct frees */
//     unyte_udp_free_all(seg);
//   }

//   printf("Shutdown the socket\n");
//   close(*collector->sockfd);
//   pthread_join(*collector->main_thread, NULL);

//   // freeing collector mallocs
//   unyte_udp_free_collector(collector);
//   fflush(stdout);
  return 0;
}
