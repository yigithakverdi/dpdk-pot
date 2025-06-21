#include "pprocess.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <stdint.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"

enum role global_role = ROLE_INGRESS;

uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {
    // egress key (16 bytes), pad with zeros if HMAC_MAX_LENGTH > 16
    {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x30, 0x4b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0,
     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0},
    // transit key (16 bytes), pad with zeros if needed
    {0xd8, 0xf9, 0xcd, 0xe1, 0xab, 0x34, 0x5c, 0xd0, 0xef, 0x67, 0x89, 0xab, 0x12, 0xcd, 0xef, 0x34,
     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0}};

void remove_headers(struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);
  
  // Find the actual UDP payload (after all headers)
  uint8_t *actual_payload = (uint8_t *)(pot + 1);

  // Add detailed packet layout analysis for debugging
  printf("PACKET LAYOUT ANALYSIS:\n");
  printf("Total packet length: %u\n", rte_pktmbuf_pkt_len(pkt));
  printf("Ethernet header: %lu bytes\n", sizeof(struct rte_ether_hdr));
  printf("IPv6 header: %lu bytes\n", sizeof(struct rte_ipv6_hdr));
  printf("SRH header: %lu bytes\n", sizeof(struct ipv6_srh));
  printf("HMAC TLV: %lu bytes\n", sizeof(struct hmac_tlv));
  printf("POT TLV: %lu bytes\n", sizeof(struct pot_tlv));
  
  // Examine what's after POT
  uint8_t *ptr_after_pot = (uint8_t *)(pot + 1);
  printf("First 16 bytes after POT (actual payload): ");
  for (int i = 0; i < 16 && i < (rte_pktmbuf_pkt_len(pkt) - (ptr_after_pot - rte_pktmbuf_mtod(pkt, uint8_t *))); i++) {
    printf("%02x ", ptr_after_pot[i]);
  }
  printf("\n");

  // Calculate headers sizes more precisely
  size_t eth_ipv6_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr);
  size_t srh_size = sizeof(struct ipv6_srh);
  size_t hmac_size = sizeof(struct hmac_tlv);
  size_t pot_size = sizeof(struct pot_tlv);
  size_t all_headers_size = eth_ipv6_size + srh_size + hmac_size + pot_size;

  // Calculate the actual payload size
  size_t actual_payload_size = rte_pktmbuf_pkt_len(pkt) - all_headers_size;
  printf("Actual UDP payload size: %lu bytes\n", actual_payload_size);

  // Save the actual payload
  uint8_t *tmp_payload = malloc(actual_payload_size);
  if (!tmp_payload) {
    printf("malloc failed\n");
    return;
  }
  memcpy(tmp_payload, actual_payload, actual_payload_size);

  // Dump the first few bytes of the actual payload
  printf("First %lu bytes of actual payload: ", (actual_payload_size > 16) ? 16 : actual_payload_size);
  for (size_t i = 0; i < 16 && i < actual_payload_size; i++) {
    printf("%02x ", tmp_payload[i]);
  }
  printf("\n");

  // Trim all headers except Ethernet and IPv6
  rte_pktmbuf_trim(pkt, rte_pktmbuf_pkt_len(pkt) - eth_ipv6_size);

  // Get IPv6 header again after trimming
  eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);

  // Update IPv6 header
  ipv6_hdr->proto = IPPROTO_UDP;

  // Set destination to iperf server
  struct in6_addr iperf_server_ipv6;
  if (inet_pton(AF_INET6, "2a05:d014:dc7:12c2:724:c0e1:c16d:2f16", &iperf_server_ipv6) != 1) {
    printf("Error converting IPv6 address\n");
    free(tmp_payload);
    return;
  }
  memcpy(&ipv6_hdr->dst_addr, &iperf_server_ipv6, sizeof(struct in6_addr));

  // Add UDP header
  struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)rte_pktmbuf_append(pkt, sizeof(struct rte_udp_hdr));
  udp_hdr->src_port = rte_cpu_to_be_16(15618);  // Use consistent port from original
  udp_hdr->dst_port = rte_cpu_to_be_16(5201);   // Standard iperf port
  udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + actual_payload_size);
  udp_hdr->dgram_cksum = 0;

  // Append the saved payload
  void *new_payload = rte_pktmbuf_append(pkt, actual_payload_size);
  memcpy(new_payload, tmp_payload, actual_payload_size);
  free(tmp_payload);

  // Update IPv6 length
  ipv6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + actual_payload_size);
  
  // Calculate the UDP checksum correctly
  udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udp_hdr);
  
  printf("UDP checksum calculated: 0x%04x\n", rte_be_to_cpu_16(udp_hdr->dgram_cksum));
}

// Functions appends an SRH structure immidiately after the IPv6 header in the packet.
// This header contains fields such as:
//
// - next_header: the type of the next header (e.g., TCP, UDP)
// - hdr_ext_len: the length of the SRH in 8-byte units
// - routing_type: the type of routing (4 for SRv6)
// - segments_left: the number of segments left to visit
// - last_entry: the last entry in the SRH
//
// and an array of IPv6 segments that represent the path the packet should take.
// This effectively inserts a segment routing header into the packet.
//
// Right after the SRH addition, an HMAC TLV (Type-Length-Value) structure is appended
// to the packet. This structure is reserved to carry a computed HMAC value for integrity
// verification. Later on the forwarding loop (for operation_bypass_bit == 0) the code,
// realings the pointers to access SRH, HMAC TLV and POT headers.
//
// It then computes an HMAC (using OpenSSL's HMAC with SHA-256) over the selected fields
// of the packet, and writes the result into the `hmac->hmac_value` field of the HMAC
// TLV structure.
void add_custom_header(struct rte_mbuf *pkt) {
  // Packet must be large enough to hold the new headers
  if (rte_pktmbuf_tailroom(pkt) < sizeof(struct ipv6_srh) + sizeof(struct hmac_tlv)) {
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "Packet too small for custom headers\n");
    return;
  }

  // Packet headers and payload pointers
  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
  uint8_t *tmp_payload = rte_malloc("tmp_payload", payload_size, RTE_CACHE_LINE_SIZE);
  if (tmp_payload == NULL) {
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "rte_malloc failed\n");
    return;
  }

  // Move the payload to a temporary buffer
  rte_memcpy(tmp_payload, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  // Add the custom headers in order and finally add the payload back
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  hmac_hdr = (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
  pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  // Reinsert the payload
  rte_memcpy(payload, tmp_payload, payload_size);
  rte_free(tmp_payload);

  // Populate the newly added headers through `rte_pktmbuf_append` on the above.
  pot_hdr->type = 1;
  pot_hdr->length = 48;
  pot_hdr->reserved = 0;
  pot_hdr->nonce_length = 16;
  pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
  memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
  memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));

  hmac_hdr->type = 5;
  hmac_hdr->length = 16;
  hmac_hdr->d_flag = 0;
  hmac_hdr->reserved = 0;
  hmac_hdr->hmac_key_id = rte_cpu_to_be_32(0);  // Set to 0 for HMAC test
  memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));

  srh_hdr->next_header = 61;
  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 1;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 2;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {{.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b,
                                             0xf3, 0xe1, 0x82, 0xc7, 0xb4}},
                                {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0x09, 0x81, 0x69, 0xd7,
                                             0xd9, 0x3b, 0xcb, 0xd2, 0xb3}}};

  memcpy(srh_hdr->segments, segments, sizeof(segments));
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");

  // Update IPv6 payload length to include new extension headers
  uint16_t new_plen = rte_pktmbuf_pkt_len(pkt) - sizeof(*eth_hdr_6) - sizeof(*ipv6_hdr);
  ipv6_hdr->payload_len = rte_cpu_to_be_16(new_plen);
  printf("[INGRESS] Updated IPv6 payload_len: %u\n", new_plen);

  // Dump the first 128 bytes (or the whole packet if smaller)
  size_t dump_len = rte_pktmbuf_pkt_len(pkt);
  if (dump_len > 128) dump_len = 128;
  printf("Packet hex dump after custom header addition (first %zu bytes):\n", dump_len);
  hex_dump(rte_pktmbuf_mtod(pkt, void *), dump_len);
}

void add_custom_header_only(struct rte_mbuf *pkt) {
  // Packet must be large enough to hold the new headers
  if (rte_pktmbuf_tailroom(pkt) < sizeof(struct ipv6_srh)) {  // Adjusted tailroom check
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "Packet too small for custom headers\\n");
    return;
  }

  // Packet headers and payload pointers
  struct ipv6_srh *srh_hdr;
  // struct hmac_tlv *hmac_hdr; // Removed unused variable
  // struct pot_tlv *pot_hdr;   // Removed unused variable
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
  uint8_t *tmp_payload = rte_malloc("tmp_payload", payload_size, RTE_CACHE_LINE_SIZE);
  if (tmp_payload == NULL) {
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "rte_malloc failed\n");
    return;
  }

  // Move the payload to a temporary buffer
  rte_memcpy(tmp_payload, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  // Add the custom headers in order and finally add the payload back
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  // Reinsert the payload
  rte_memcpy(payload, tmp_payload, payload_size);
  rte_free(tmp_payload);

  srh_hdr->next_header = 61;
  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 1;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 1;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {{.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b,
                                             0xf3, 0xe1, 0x82, 0xc7, 0xb4}},

                                {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x12, 0x09, 0x81, 0x69, 0xd7, 0xd9, 0x3b,
                                             0xcb, 0xd2, 0xb3, 0x00, 0x00}}};
  memcpy(srh_hdr->segments, segments, sizeof(segments));

  // Log als the segments
  printf("SRH segments:\n");
  for (int i = 0; i < srh_hdr->segments_left; i++) {
    char segment_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &srh_hdr->segments[i], segment_str, sizeof(segment_str)) == NULL) {
      perror("inet_ntop failed");
    } else {
      printf("Segment %d: %s\n", i, segment_str);
    }
  }
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");
}

// Helper: process a single packet for ingress
static inline void process_ingress_packet(struct rte_mbuf *mbuf, uint16_t rx_port_id) {
  printf("[INGRESS] Packet hex dump BEFORE processing (first 64 bytes):\n");
  size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
  if (dump_len > 64) dump_len = 64;
  hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
  printf("[INGRESS] Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
  printf("[INGRESS] mbuf nb_segs: %u\n", mbuf->nb_segs);
  printf("[INGRESS] tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf), mbuf->data_len);

  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // 1. Skip non-IPv6
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    printf("Ingress: Not an IPv6 packet, skipping and freeing mbuf\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  // 2. Skip non-unicast (multicast/broadcast) destination MAC
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    printf("Ingress: Multicast/Broadcast MAC, skipping and freeing mbuf\n");
    // Print more info for debugging
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->dst_addr.addr_bytes[0],
           eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    printf("  IPv6 src: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "");
    printf("  IPv6 dst: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "");
    printf("  EtherType: 0x%04x\n", ether_type);
    printf("  Next header: %u\n", ipv6_hdr->proto);
    if (ipv6_hdr->proto == IPPROTO_UDP) {
      struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);
      printf("  UDP src port: %u, dst port: %u\n", ntohs(udp_hdr->src_port), ntohs(udp_hdr->dst_port));
    } else if (ipv6_hdr->proto == IPPROTO_TCP) {
      struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);
      printf("  TCP src port: %u, dst port: %u\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));
    }
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0:
          printf("Processing IPv6 packet with operation_bypass_bit = 0\n");
          add_custom_header(mbuf);
          // Print after header addition
          printf("[INGRESS] After header addition: Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
          printf("[INGRESS] After header addition: mbuf nb_segs: %u\n", mbuf->nb_segs);
          printf("[INGRESS] After header addition: tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf),
                 mbuf->data_len);

          // Realign pointers after header addition
          printf("Realigning pointers after adding custom headers\n");
          struct rte_ether_hdr *eth_hdr6 = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr6 + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          // Print offsets and hex dumps for debugging
          print_offset_and_hex("[INGRESS] SRH", eth_hdr6, srh, sizeof(struct ipv6_srh));
          print_offset_and_hex("[INGRESS] HMAC TLV", eth_hdr6, hmac, sizeof(struct hmac_tlv));
          print_offset_and_hex("[INGRESS] POT TLV", eth_hdr6, pot, sizeof(struct pot_tlv));

          // Extract destination IPv6 address as string
          printf("Extracting destination IPv6 address\n");
          char dst_ip_str[INET6_ADDRSTRLEN];
          if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
            perror("inet_ntop failed");
            break;
          }

          // Prepare k_pot_in array using the loaded key for all SIDs
          // printf("Preparing k_pot_in array for all SIDs\n");
          // uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {0};
          // for (int sid = 0; sid < SID_NO; sid++) {
          //   if (read_encryption_key("keys.txt", dst_ip_str, k_pot_in[sid], HMAC_MAX_LENGTH) != 0) {
          //     printf("Failed to read key for %s\n", dst_ip_str);
          //     break;
          //   }
          // }

          printf("Debug: k_pot_in array contents:\n");
          for (int i = 0; i < SID_NO; i++) {
            printf("SID %d: ", i);
            for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
              printf("%02x", k_pot_in[i][j]);
            }
            printf("\n");
          }

          // Prepare HMAC key (use same as encryption key for demo)
          // printf("Preparing HMAC key for HMAC computation\n");
          // uint8_t k_hmac_ie[HMAC_MAX_LENGTH] = {0};
          // if (read_encryption_key("keys.txt", dst_ip_str, k_hmac_ie, HMAC_MAX_LENGTH) != 0) {
          //   printf("Failed to read HMAC key for %s\n", dst_ip_str);
          //   break;
          // }
          uint8_t *k_hmac_ie = k_pot_in[0];  // egress key
          size_t key_len = HMAC_MAX_LENGTH;

          // Compute HMAC
          printf("Computing HMAC for the packet\n");
          // Log HMAC input values for debugging
          struct in6_addr ingress_addr;
          inet_pton(AF_INET6, "2a05:d014:dc7:1291:11ed:eb6b:b01a:9452", &ingress_addr);
          printf("[INGRESS] HMAC input values (FORCED ingress IP):\n");
          printf("  src_addr: 2a05:d014:dc7:1291:11ed:eb6b:b01a:9452\n");
          printf("  srh->last_entry: %u\n", srh->last_entry);
          printf("  srh->flags: %u\n", srh->flags);
          printf("  hmac->hmac_key_id: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
          printf("  srh->segments: ");
          for (int i = 0; i <= srh->last_entry; i++) {
            char seg_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &srh->segments[i], seg_str, sizeof(seg_str)))
              printf("%s ", seg_str);
            else
              perror("inet_ntop segment");
          }
          printf("\n");
          // Dump the first 128 bytes (or the whole packet if smaller) after all headers and before send
          size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
          if (dump_len > 128) dump_len = 128;
          printf("[INGRESS] Packet hex dump before send (first %zu bytes):\n", dump_len);
          hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
          uint8_t hmac_out[HMAC_MAX_LENGTH];
          if (calculate_hmac((uint8_t *)&ingress_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0) {
            printf("HMAC Computation Successful\nHMAC: ");
            for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
            printf("\n");
            rte_memcpy(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH);
            printf("HMAC value inserted to srh_hmac header\n");

            // Dump the first 128 bytes (or the whole packet if smaller) after HMAC is written
            size_t dump_len_after_hmac = rte_pktmbuf_pkt_len(mbuf);
            if (dump_len_after_hmac > 128) dump_len_after_hmac = 128;
            printf("[INGRESS] Packet hex dump AFTER HMAC write (first %zu bytes):\n", dump_len_after_hmac);
            hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len_after_hmac);
            printf("HMAC value inserted to srh_hmac header\n");
          } else {
            printf("HMAC Computation Failed\n");
            break;
          }

          // Nonce Generation and Encryption (PVF Computation)
          printf("Generating nonce and encrypting PVF\n");
          uint8_t nonce[NONCE_LENGTH];
          if (generate_nonce(nonce) != 0) {
            printf("Nonce generation failed, returning\n");
            break;
          }
          encrypt_pvf(k_pot_in, nonce, hmac_out);
          printf("Encrypted PVF before writing to the header: ");
          for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
          printf("\n");
          rte_memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
          rte_memcpy(pot->nonce, nonce, NONCE_LENGTH);
          printf("Encrypted PVF and nonce values inserted to pot header\n");

          // Forward the packet using the `send_packet_to` function
          printf("Forwarding packet to next hop\n");

          if (srh->segments_left == 0) {
            printf("No segments left in SRH, would not forward.\n");
          } else {
            // Compute next-hop index such that ingress picks first segment and transit picks second
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            char next_sid_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &srh->segments[next_sid_index], next_sid_str, sizeof(next_sid_str)) ==
                NULL) {
              perror("inet_ntop failed for next segment");
            } else {
              printf("Next segment IPv6 (from SRH): %s\n", next_sid_str);
            }

            // Lookup MAC for next segment
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {
              printf("Resolved next-hop MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", next_mac->addr_bytes[0],
                     next_mac->addr_bytes[1], next_mac->addr_bytes[2], next_mac->addr_bytes[3],
                     next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
            } else {
              printf("No MAC mapping found for next segment IPv6!\n");
            }

            // Store original DstIP (ingress's own IP for this interface) to use as SrcIP later
            struct in6_addr ingress_own_ip_as_src;
            memcpy(&ingress_own_ip_as_src, &ipv6_hdr->dst_addr, sizeof(struct in6_addr));

            // Update the main IPv6 header's Destination Address to the next segment.
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(struct in6_addr));

            // Update the main IPv6 header's Source Address to the ingress node's own IP.
            memcpy(&ipv6_hdr->src_addr, &ingress_own_ip_as_src, sizeof(struct in6_addr));

            // Get the MAC address of the ingress DPDK port (which will be the source MAC)
            struct rte_ether_addr ingress_port_mac;
            rte_eth_macaddr_get(rx_port_id, &ingress_port_mac);

            // Print what the packet's destination/source MAC and IPv6 would be
            printf("Packet would be sent with:\n");
            printf("  Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", ingress_port_mac.addr_bytes[0],
                   ingress_port_mac.addr_bytes[1], ingress_port_mac.addr_bytes[2],
                   ingress_port_mac.addr_bytes[3], ingress_port_mac.addr_bytes[4],
                   ingress_port_mac.addr_bytes[5]);
            if (next_mac) {
              printf("  Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", next_mac->addr_bytes[0],
                     next_mac->addr_bytes[1], next_mac->addr_bytes[2], next_mac->addr_bytes[3],
                     next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
            }
            printf("  Src IPv6: ");
            print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "");
            printf("  Dst IPv6: ");
            print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "");

            // Actually send the packet
            if (next_mac) {
              send_packet_to(*next_mac, mbuf, rx_port_id);
              printf("[INGRESS] Packet hex dump AFTER send (first 64 bytes):\n");
              dump_len = rte_pktmbuf_pkt_len(mbuf);
              if (dump_len > 64) dump_len = 64;
              hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
              printf("[INGRESS] After send: Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
              printf("[INGRESS] After send: mbuf nb_segs: %u\n", mbuf->nb_segs);
              printf("[INGRESS] After send: tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf),
                     mbuf->data_len);
            } else {
              printf("No MAC address found for next segment, dropping packet\n");
              rte_pktmbuf_free(mbuf);
            }
          }

          break;
        case 1:
          // Bypass all operations
          break;
        case 2: add_custom_header_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t rx_port_id) {
  printf("Starting process on ingress role with %u packets\n", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_ingress_packet(pkts[i], rx_port_id);
  }
}

// Helper: process a single packet for transit
static inline void process_transit_packet(struct rte_mbuf *mbuf, int i) {
  printf("[TRANSIT] Packet hex dump BEFORE processing (first 64 bytes):\n");
  size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
  if (dump_len > 64) dump_len = 64;
  hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
  printf("[TRANSIT] Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
  printf("[TRANSIT] mbuf nb_segs: %u\n", mbuf->nb_segs);
  printf("[TRANSIT] tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf), mbuf->data_len);

  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // Skip non-unicast (multicast/broadcast) destination MAC
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    printf("Transit: Multicast/Broadcast MAC, skipping and freeing mbuf\n");
    // Print more info for debugging
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->dst_addr.addr_bytes[0],
           eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    printf("  IPv6 src: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "");
    printf("  IPv6 dst: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "");
    printf("  EtherType: 0x%04x\n", ether_type);
    printf("  Next header: %u\n", ipv6_hdr->proto);
    if (ipv6_hdr->proto == IPPROTO_UDP) {
      struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);
      printf("  UDP src port: %u, dst port: %u\n", ntohs(udp_hdr->src_port), ntohs(udp_hdr->dst_port));
    } else if (ipv6_hdr->proto == IPPROTO_TCP) {
      struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);
      printf("  TCP src port: %u, dst port: %u\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));
    }
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0: {
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          // Only process packets with your SRH
          if (srh->next_header != 61 || srh->routing_type != 4) {
            printf("Packet %d: Not a valid SRH packet, skipping\n", i + 1);
            rte_pktmbuf_free(mbuf);
            return;
          }

          if (srh->next_header == 61) {
            printf("SRH detected at transit node \n");

            // struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
            // struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);
            // compute SRH total size in bytes
            size_t srh_bytes = sizeof(struct ipv6_srh);
            // hmac TLV follows immediately
            uint8_t *hmac_ptr = (uint8_t *)srh + srh_bytes;
            struct hmac_tlv *hmac = (struct hmac_tlv *)hmac_ptr;
            // pot TLV follows right after the HMAC TLV
            uint8_t *pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
            struct pot_tlv *pot = (struct pot_tlv *)pot_ptr;

            // Print offsets and hex dumps for debugging
            print_offset_and_hex("[TRANSIT] SRH", eth_hdr, srh, sizeof(struct ipv6_srh));
            print_offset_and_hex("[TRANSIT] HMAC TLV", eth_hdr, hmac, sizeof(struct hmac_tlv));
            print_offset_and_hex("[TRANSIT] POT TLV", eth_hdr, pot, sizeof(struct pot_tlv));

            printf("[TRANSIT] Raw HMAC TLV bytes: ");
            hex_dump((void *)hmac, sizeof(struct hmac_tlv));
            printf("[TRANSIT] hmac->hmac_key_id: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));

            // Display source and destination MAC addresses
            printf("Packet %d:\n", i + 1);
            printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
                   "\n",
                   eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
                   eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
                   eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
            printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
                   "\n",
                   eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                   eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                   eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
            printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));

            print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "source");
            print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "destination");

            printf("The size of srh is %lu\n", sizeof(*srh));
            printf("The size of hmac is %lu\n", sizeof(*hmac));
            printf("The size of pot is %lu\n", sizeof(*pot));

            printf("HMAC type: %u\n", hmac->type);
            printf("HMAC length: %u\n", hmac->length);
            printf("HMAC key ID: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
            printf("HMAC size: %ld\n", sizeof(hmac->hmac_value));

            // Decrypt the POT field (PVF) if needed
            char dst_ip_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              perror("inet_ntop failed");
              rte_pktmbuf_free(mbuf);
              return;
            }

            // uint8_t k_pot_in_transit[1][HMAC_MAX_LENGTH] = {{0}};  // Changed declaration
            // if (read_encryption_key("keys.txt", dst_ip_str, k_pot_in_transit[0], HMAC_MAX_LENGTH) !=
            //     0) {  // Read into k_pot_in_transit[0]
            //   printf("Failed to read key for %s\n", dst_ip_str);
            //   rte_pktmbuf_free(mbuf);
            //   return;
            // }

            printf("Decrypting PVF for %s\n", dst_ip_str);
            uint8_t pvf_out[HMAC_MAX_LENGTH];
            // memcpy(pvf_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);
            // decrypt_pvf(k_pot_in_transit, pot->nonce, pvf_out);  // Use k_pot_in_transit
            // memcpy(pot->encrypted_hmac, pvf_out, HMAC_MAX_LENGTH);
            memcpy(pvf_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);
            // decrypt_pvf(k_pot_in_transit, pot->nonce, pvf_out);
            decrypt_pvf(&k_pot_in[1], pot->nonce, pvf_out);

            // memcpy(hmac->hmac_value, pvf_out, HMAC_MAX_LENGTH);
            memcpy(pot->encrypted_hmac, pvf_out, HMAC_MAX_LENGTH);
            printf("Transit: Updated HMAC field with decrypted PVF\n");
            printf("[TRANSIT] Decrypted PVF:\n");
            for (int j = 0; j < HMAC_MAX_LENGTH; j++) printf("%02x", pvf_out[j]);
            printf("\n[TRANSIT] HMAC field after update:\n");
            for (int j = 0; j < HMAC_MAX_LENGTH; j++) printf("%02x", hmac->hmac_value[j]);
            printf("\n");

            // SRH forwarding logic
            if (srh->segments_left == 0) {
              printf("Transit: No more segments left, dropping or processing as egress\n");
              rte_pktmbuf_free(mbuf);
              return;
            }

            // Decrement segments_left before computing next hop
            srh->segments_left--;
            // Compute next-hop index: = last_entry - segments_left + 1
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            printf("Transit: Forwarding to next segment, segments left: %d, next index: %d\n",
                   srh->segments_left, next_sid_index);
            // Update IPv6 dst to selected segment
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(ipv6_hdr->dst_addr));
            // Lookup MAC for new IPv6 destination
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            char next_ip_str[INET6_ADDRSTRLEN];
            printf("Transit: Next segment IPv6: %s\n",
                   inet_ntop(AF_INET6, &srh->segments[next_sid_index], next_ip_str, sizeof(next_ip_str)));
            if (next_mac) {
              printf("Transit: Found MAC for next segment: %02X:%02X:%02X:%02X:%02X:%02X\n",
                     next_mac->addr_bytes[0], next_mac->addr_bytes[1], next_mac->addr_bytes[2],
                     next_mac->addr_bytes[3], next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
              send_packet_to(*next_mac, mbuf, /*tx_port_id*/ 0);
              printf("[TRANSIT] Packet hex dump AFTER send (first 64 bytes):\n");
              dump_len = rte_pktmbuf_pkt_len(mbuf);
              if (dump_len > 64) dump_len = 64;
              hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
              printf("[TRANSIT] After send: Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
              printf("[TRANSIT] After send: mbuf nb_segs: %u\n", mbuf->nb_segs);
              printf("[TRANSIT] After send: tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf),
                     mbuf->data_len);
            } else {
              printf("Transit: No MAC mapping for next segment!\n");
              rte_pktmbuf_free(mbuf);
            }
          }
          break;
        }  // Added braces for case block
        case 1:
          // Bypass all operations
          break;
        // case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_transit_packet(pkts[i], i);
  }
}

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf) {
  if (memcmp(hmac->hmac_value, hmac_out, 32) != 0) {
    printf("The decrypted hmac is not the same as the computed hmac\n");
    printf("dropping the packet\n");
    rte_pktmbuf_free(mbuf);
    return 0;
  } else {
    printf("The transit of the packet is verified\n");
    // forward it to the tap interface so iperf can catch it
    return 1;
  }
}

// Helper: process a single packet for egress
static inline void process_egress_packet(struct rte_mbuf *mbuf) {
  printf("[EGRESS] Packet hex dump BEFORE processing (first 64 bytes):\n");
  size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
  if (dump_len > 64) dump_len = 64;
  hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
  printf("[EGRESS] Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
  printf("[EGRESS] mbuf nb_segs: %u\n", mbuf->nb_segs);
  printf("[EGRESS] tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf), mbuf->data_len);

  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  printf("EGRESS DEBUG: First 32 bytes: ");
  hex_dump(rte_pktmbuf_mtod(mbuf, void *), 32);
  printf("EGRESS DEBUG: Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
  printf("EGRESS DEBUG: EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0: {
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          if (srh->next_header == 61) {
            printf("Egress: SRH detected, processing packet\n");

            size_t srh_bytes = sizeof(struct ipv6_srh);
            uint8_t *hmac_ptr = (uint8_t *)srh + srh_bytes;
            struct hmac_tlv *hmac = (struct hmac_tlv *)hmac_ptr;
            uint8_t *pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
            struct pot_tlv *pot = (struct pot_tlv *)pot_ptr;

            // Print offsets and hex dumps for debugging
            print_offset_and_hex("[EGRESS] SRH", eth_hdr, srh, sizeof(struct ipv6_srh));
            print_offset_and_hex("[EGRESS] HMAC TLV", eth_hdr, hmac, sizeof(struct hmac_tlv));
            print_offset_and_hex("[EGRESS] POT TLV", eth_hdr, pot, sizeof(struct pot_tlv));

            // Read key for this egress node from keys.txt
            char dst_ip_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              perror("inet_ntop failed");
              rte_pktmbuf_free(mbuf);
              return;
            }

            // uint8_t k_pot_in_egress[1][HMAC_MAX_LENGTH] = {{0}};
            // if (read_encryption_key("keys.txt", dst_ip_str, k_pot_in_egress[0], HMAC_MAX_LENGTH) != 0) {
            //   printf("Egress: Failed to read key for %s\n", dst_ip_str);
            //   rte_pktmbuf_free(mbuf);
            //   return;
            // }

            // Decrypt PVF
            uint8_t hmac_out[HMAC_MAX_LENGTH];
            memcpy(hmac_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);
            // decrypt_pvf(k_pot_in_egress, pot->nonce, hmac_out);
            decrypt_pvf(&k_pot_in[0], pot->nonce, hmac_out);
            memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
            printf("[EGRESS] Decrypted PVF:\n");
            for (int j = 0; j < HMAC_MAX_LENGTH; j++) printf("%02x", hmac_out[j]);
            printf("\n[EGRESS] HMAC field in header:\n");
            for (int j = 0; j < HMAC_MAX_LENGTH; j++) printf("%02x", hmac->hmac_value[j]);
            printf("\n");

            // Prepare HMAC key (use same as encryption key for demo)
            // uint8_t k_hmac_ie[HMAC_MAX_LENGTH] = {0};
            // if (read_encryption_key("keys.txt", dst_ip_str, k_hmac_ie, HMAC_MAX_LENGTH) != 0) {
            //   printf("Egress: Failed to read HMAC key for %s\n", dst_ip_str);
            //   rte_pktmbuf_free(mbuf);
            //   return;
            // }
            uint8_t *k_hmac_ie = k_pot_in[0];  // egress key

            // Log HMAC input values for debugging
            printf("[EGRESS] HMAC input values:\n");
            printf("  src_addr: ");
            char src_addr_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_addr_str, sizeof(src_addr_str)))
              printf("%s\n", src_addr_str);
            else
              perror("inet_ntop src_addr");
            printf("  srh->last_entry: %u\n", srh->last_entry);
            printf("  srh->flags: %u\n", srh->flags);
            printf("  hmac->hmac_key_id: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
            printf("  srh->segments: ");
            for (int i = 0; i <= srh->last_entry; i++) {
              char seg_str[INET6_ADDRSTRLEN];
              if (inet_ntop(AF_INET6, &srh->segments[i], seg_str, sizeof(seg_str)))
                printf("%s ", seg_str);
              else
                perror("inet_ntop segment");
            }
            printf("\n");
            uint8_t expected_hmac[HMAC_MAX_LENGTH];
            if (calculate_hmac((uint8_t *)&ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, HMAC_MAX_LENGTH,
                               expected_hmac) != 0) {
              printf("[EGRESS] Expected HMAC:\n");
              for (int j = 0; j < HMAC_MAX_LENGTH; j++) printf("%02x", expected_hmac[j]);
              printf("\n");
              printf("Egress: HMAC calculation failed\n");
              rte_pktmbuf_free(mbuf);
              return;
            }

            // Compare decrypted PVF with expected HMAC
            if (memcmp(hmac_out, expected_hmac, HMAC_MAX_LENGTH) != 0) {
              printf("Egress: HMAC verification failed, dropping packet\n");
              rte_pktmbuf_free(mbuf);
              return;
            } else {
              printf("Egress: HMAC verified successfully, forwarding packet\n");
            }

            // Remove headers and forward to iperf server (replace MAC/port as needed)
            remove_headers(mbuf);

            // After modifying headers but before sending:
            struct rte_ether_hdr *eth_hdr_final = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            struct rte_ipv6_hdr *ipv6_hdr_final = (struct rte_ipv6_hdr *)(eth_hdr_final + 1);
            // Detailed UDP header verification before sending
            if (ipv6_hdr_final->proto == IPPROTO_UDP) {
              struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr_final + 1);

              // Print detailed information about the UDP header
              printf("\n[EGRESS] UDP HEADER VERIFICATION\n");
              printf("UDP Source Port: %u\n", rte_be_to_cpu_16(udp_hdr->src_port));
              printf("UDP Destination Port: %u\n", rte_be_to_cpu_16(udp_hdr->dst_port));
              printf("UDP Length: %u\n", rte_be_to_cpu_16(udp_hdr->dgram_len));
              printf("UDP Checksum: 0x%04x\n", rte_be_to_cpu_16(udp_hdr->dgram_cksum));

              // Check UDP payload size matches declared length
              uint16_t expected_udp_len = rte_be_to_cpu_16(udp_hdr->dgram_len);
              uint16_t ipv6_payload_len = rte_be_to_cpu_16(ipv6_hdr_final->payload_len);

              printf("IPv6 Payload Length: %u\n", ipv6_payload_len);
              printf("Expected UDP Length (from header): %u\n", expected_udp_len);

              if (ipv6_payload_len != expected_udp_len) {
                printf("WARNING: IPv6 payload length (%u) doesn't match UDP length (%u)\n", ipv6_payload_len,
                       expected_udp_len);
              } else {
                printf("IPv6 payload length matches UDP length\n");
              }

              // Dump the UDP payload (first few bytes)
              uint8_t *udp_payload = (uint8_t *)(udp_hdr + 1);
              size_t payload_dump_len = 32;  // Show first 32 bytes of payload
              size_t max_dump_len =
                  rte_pktmbuf_pkt_len(mbuf) - ((uint8_t *)udp_payload - rte_pktmbuf_mtod(mbuf, uint8_t *));

              if (payload_dump_len > max_dump_len) {
                payload_dump_len = max_dump_len;
              }

              printf("UDP Payload (first %zu bytes):\n", payload_dump_len);
              hex_dump(udp_payload, payload_dump_len);

              // No need to zero out the checksum, we've properly calculated it in remove_headers
              printf("UDP Checksum properly calculated and ready for delivery\n");
            } else {
              printf("[EGRESS] WARNING: Expected UDP protocol (17) but got protocol %u\n",
                     ipv6_hdr_final->proto);
            }

            // struct rte_ether_addr iperf_mac = {{0x08, 0x00, 0x27, 0x7D, 0xDD, 0x01}};
            struct rte_ether_addr iperf_mac = {
                {0x02, 0x38, 0x81, 0xe2, 0xf9, 0xa7}};  // Updated to your iperf server MAC
                                                        // send_packet_to(iperf_mac, mbuf, /*tx_port_id*/ 1);
            printf("[EGRESS] Sending packet to iperf server MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   iperf_mac.addr_bytes[0], iperf_mac.addr_bytes[1], iperf_mac.addr_bytes[2],
                   iperf_mac.addr_bytes[3], iperf_mac.addr_bytes[4], iperf_mac.addr_bytes[5]);
            send_packet_to(iperf_mac, mbuf, 0);
            printf("[EGRESS] Packet hex dump AFTER send (first 64 bytes):\n");
            dump_len = rte_pktmbuf_pkt_len(mbuf);
            if (dump_len > 64) dump_len = 64;
            hex_dump(rte_pktmbuf_mtod(mbuf, void *), dump_len);
            printf("[EGRESS] After send: Packet length: %u\n", rte_pktmbuf_pkt_len(mbuf));
            printf("[EGRESS] After send: mbuf nb_segs: %u\n", mbuf->nb_segs);
            printf("[EGRESS] After send: tailroom: %u, data_len: %u\n", rte_pktmbuf_tailroom(mbuf),
                   mbuf->data_len);
          }
          break;
        }
        case 1:
          // Bypass all operations
          break;
        // case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_egress_packet(pkts[i]);
  }
}

int lcore_main_forward(void *arg) {
  printf("Starting lcore_main_forward\n");

  // Parse arguments (ports) from input.
  uint16_t *ports = (uint16_t *)arg;
  uint16_t rx_port_id = ports[0];
  // uint16_t tx_port_id = ports[1]; // Assuming tx_port_id might be needed later
  printf("RX Port ID: %u\n",
         rx_port_id);  // Removed TX Port ID from this line as it's not used yet in this context

  enum role cur_role = global_role;  // Use global_role set from main.c
  printf("Current role: %s\n",
         cur_role == ROLE_INGRESS ? "INGRESS" : (cur_role == ROLE_TRANSIT ? "TRANSIT" : "EGRESS"));

  // Main processing loop.
  printf("Entering main forwarding loop on lcore %u\n", rte_lcore_id());
  while (1) {
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts, BURST_SIZE);

    if (nb_rx == 0) continue;

    if (nb_rx > 0) {
      struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);
      printf("Received %u packets on port %u, EtherType: 0x%04x\n", nb_rx, rx_port_id,
             rte_be_to_cpu_16(eth_hdr->ether_type));
      uint8_t *data = rte_pktmbuf_mtod(pkts[0], uint8_t *);
      printf("First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7]);
    }

    // Route packet batch to the appropriate processing logic.
    switch (cur_role) {
      case ROLE_INGRESS: process_ingress(pkts, nb_rx, rx_port_id); break;
      case ROLE_TRANSIT: process_transit(pkts, nb_rx); break;
      case ROLE_EGRESS: process_egress(pkts, nb_rx); break;
      default: break;
    }

    // Send processed packets out.
    // uint16_t nb_tx = rte_eth_tx_burst(tx_port_id, 0, pkts, nb_rx);

    // Free any unsent packets.
    // if (nb_tx < nb_rx) {
    //   uint16_t i;
    //   for (i = nb_tx; i < nb_rx; i++) rte_pktmbuf_free(pkts[i]);
    // }
  }
  return 0;
}

void launch_lcore_forwarding(uint16_t *ports) {
  unsigned lcore_id = rte_get_next_lcore(-1, 1, 0);
  rte_eal_remote_launch(lcore_main_forward, (void *)ports, lcore_id);
  rte_eal_mp_wait_lcore();  // Wait for all lcores to finish (optional, for clean shutdown)
}

// Utility: Print offset and hex for a structure
void print_offset_and_hex(const char *label, const void *base, const void *ptr, size_t len) {
  printf("%s offset: %ld\n", label, (const uint8_t *)ptr - (const uint8_t *)base);
  printf("%s hex dump:\n", label);
  hex_dump(ptr, len);
}