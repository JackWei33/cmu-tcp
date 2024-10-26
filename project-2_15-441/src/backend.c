/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))


long long current_timestamp_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)(tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
}

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  switch (flags) {
    case SYN_FLAG_MASK: {
      sock->hs_syn_received = true;
      sock->window.next_seq_expected = get_seq(hdr) + 1;

      break;
    }
    case (ACK_FLAG_MASK | SYN_FLAG_MASK): {
      if (get_ack(hdr) == sock->hs_syn_ack_expected_ack) {
        sock->window.next_seq_expected = get_seq(hdr) + 1;
        sock->window.last_ack_received = get_ack(hdr);

        // SENDS BACK ACK
        socklen_t conn_len = sizeof(sock->conn);
        uint32_t seq = sock->window.last_ack_received;
        uint8_t *payload = NULL;
        uint16_t payload_len = 0;
        uint16_t ext_len = 0;
        uint8_t *ext_data = NULL;

        uint16_t src = sock->my_port;
        uint16_t dst = ntohs(sock->conn.sin_port);
        uint32_t ack = sock->window.next_seq_expected;
        uint16_t hlen = sizeof(cmu_tcp_header_t);
        uint16_t plen = hlen + payload_len;
        uint8_t flags = ACK_FLAG_MASK;
        uint16_t adv_window = 1;
        uint8_t *response_packet =
            create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
        sendto(sock->socket, response_packet, plen, 0,
              (struct sockaddr *)&(sock->conn), conn_len);
        
        free(response_packet);
      }
      break;
    }
    case ACK_FLAG_MASK: {
      if (sock->type == TCP_LISTENER && sock->in_handshake_phase && sock->hs_syn_received && !sock->hs_ack_received) {
        // Case where waiting for ack in handshake phase
        uint32_t ack = get_ack(hdr);
        if (ack == sock->window.last_ack_received + 1) {
          sock->window.last_ack_received = ack;
          sock->hs_ack_received = true;
        }
        break;
      }
      else if (!sock->in_handshake_phase) {
        // Normal ack case
        uint32_t ack = get_ack(hdr);
        if (after(ack, sock->window.last_ack_received)) {
          sock->window.last_ack_received = ack;
        }
        // Fall through to respond to message
      }
      else {
        break;
      }
    }
    default: {
      if (sock->in_handshake_phase) {
        return;
      }
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);
      if (get_payload_len(pkt) > 0) {
        sendto(sock->socket, response_packet, plen, 0,
            (struct sockaddr *)&(sock->conn), conn_len);
      }
            
      free(response_packet);

      seq = get_seq(hdr);
      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags, int timeout_length) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, timeout_length) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT, DEFAULT_TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }

      data_offset += payload_len;
    }
  }
}

void send_window(cmu_socket_t *sock, uint8_t *data, int left, int right, uint32_t initial_seq_num) {
  uint8_t *msg;
  size_t conn_len = sizeof(sock->conn);
  int sockfd = sock->socket;

  int index = left;
  while (index < right) {
    uint16_t payload_len = MIN((uint32_t)(right - index), (uint32_t)MSS);

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t seq = initial_seq_num + (uint32_t)index;
    uint32_t ack = sock->window.next_seq_expected;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = 0;
    uint16_t adv_window = 1;
    uint16_t ext_len = 0;
    uint8_t *ext_data = NULL;
    uint8_t *payload = data + index;

    msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

    sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
           conn_len);

    index += payload_len;
  }
}

void multi_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint32_t initial_seq_num = sock->window.last_ack_received;
  int left = 0;
  int right = MIN(CP1_WINDOW_SIZE, (long unsigned int)buf_len);

  while (left < buf_len) {
    // Grab whole window, send them all
    // Loop check_for_data until we time out, go back to beginning of loop
    // If something got acked, send out more data
    send_window(sock, data, left, right, initial_seq_num);
    long long last_send_ts = current_timestamp_ms();

    while (1) {
      int initial_left = left;

      int timeout_length = DEFAULT_TIMEOUT - (int)(current_timestamp_ms() - last_send_ts);
      if (timeout_length <= 0) {
        break;
      }
      check_for_data(sock, TIMEOUT, timeout_length);
      
      left = sock->window.last_ack_received - initial_seq_num;
      int acked_bytes = left - initial_left;

      send_window(sock, data, right, MIN(right + acked_bytes, buf_len), initial_seq_num);
      right = MIN(right + acked_bytes, buf_len);

      if (left >= buf_len) {
        break;
      }
    }
  }
}


void client_handshake(cmu_socket_t *sock) {
  sock->hs_syn_ack_expected_ack = sock->window.last_ack_received + 1;
  while (1) {
    if (sock->window.last_ack_received == sock->hs_syn_ack_expected_ack) {
      break;
    }
    // SEND INITIAL SYN PACKET
    socklen_t conn_len = sizeof(sock->conn);
    uint32_t seq = sock->window.last_ack_received;
    uint8_t *payload = NULL;
    uint16_t payload_len = 0;

    // No extension.
    uint16_t ext_len = 0;
    uint8_t *ext_data = NULL;

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t ack = 0;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = SYN_FLAG_MASK;
    uint16_t adv_window = 1;
    uint8_t *response_packet =
        create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                      ext_data, payload, payload_len);
    sendto(sock->socket, response_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
    free(response_packet);

    int timeout_length = DEFAULT_TIMEOUT;
    check_for_data(sock, TIMEOUT, timeout_length);
  }

  sock->in_handshake_phase = false;
}


void server_handshake(cmu_socket_t *sock) {
  while (1) {
    check_for_data(sock, NO_FLAG, 0);
    if (sock->hs_syn_received) {
      break;
    }
  }

  while (1) {
    socklen_t conn_len = sizeof(sock->conn);
    uint32_t seq = sock->window.last_ack_received;
    uint8_t *payload = NULL;
    uint16_t payload_len = 0;
    uint16_t ext_len = 0;
    uint8_t *ext_data = NULL;

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);
    uint32_t ack = sock->window.next_seq_expected;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = ACK_FLAG_MASK | SYN_FLAG_MASK;
    uint16_t adv_window = 1;
    uint8_t *response_packet =
        create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                      ext_len, ext_data, payload, payload_len);
    sendto(sock->socket, response_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
    free(response_packet);

    check_for_data(sock, TIMEOUT, DEFAULT_TIMEOUT);
    if (sock->hs_ack_received) {
      break;
    }
  }
  
  sock->in_handshake_phase = false;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  if (sock->type == TCP_INITIATOR) {
    client_handshake(sock);
  }
  else {
    server_handshake(sock);
  }

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      multi_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT, 0);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
