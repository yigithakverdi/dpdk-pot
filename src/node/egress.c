#include "node/egress.h"

#include "dataplane/forward.h"
#include "dataplane/headers.h"
#include "dataplane/processing.h"
#include "security/crypto.h"
#include "utils/common.h"
#include "utils/logging.h"

static inline void process_egress_packet(struct rte_mbuf *mbuf) {
  // LOG_MAIN(NOTICE, "Processing egress packet with length %u", rte_pktmbuf_pkt_len(mbuf));
  // LOG_MAIN(NOTICE, "Egress packet nb_segs: %u", mbuf->nb_segs);
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // Check if the packet is IPv6, if not drop it
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(NOTICE, "Non-IPv6 packet received in egress (EtherType: %u), dropping.\n", ether_type);
    rte_pktmbuf_free(mbuf);
    return;
  }
  
  // Check if the destination MAC address is a multicast/broadcast address
  // If the least significant bit of the first byte is set, it's multicast/broadcast
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    LOG_MAIN(NOTICE, "Multicast/Broadcast packet received in egress, dropping.\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      LOG_MAIN(DEBUG, "Egress packet is IPv6, processing headers\n");

      // Depending on the operation bypass bit, we either process the packet or bypass operations
      // operation_bypass_bit is a global variable that indicates whether to bypass operations
      // 0: Process packet with SRH and HMAC
      // 1: Bypass all operations
      // 2: Remove headers only (not implemented in this case)
      // This simplifies the process logic, and allows easy extension in the future
      // if needed.
      switch (operation_bypass_bit) {
        LOG_MAIN(DEBUG, "Operation bypass bit is %d\n", operation_bypass_bit);
        case 0: {
          LOG_MAIN(DEBUG, "Processing packet with SRH and HMAC\n");
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          // Check if the SRH next header is 61 (SRv6). If it is, we proceed with processing.
          // 61 is the next header type for SRv6, as per RFC 8200.
          // If the next header is not 61, we do not process the packet further
          // and simply return.
          if (srh->next_header == 61) {
            LOG_MAIN(DEBUG, "SRH detected, processing packet\n");
            size_t srh_bytes = sizeof(struct ipv6_srh);
            uint8_t *hmac_ptr = (uint8_t *)srh + srh_bytes;
            struct hmac_tlv *hmac = (struct hmac_tlv *)hmac_ptr;
            uint8_t *pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
            struct pot_tlv *pot = (struct pot_tlv *)pot_ptr;
            LOG_MAIN(DEBUG, "HMAC TLV type: %u, length: %u\n", hmac->type, hmac->length);

            // Create a buffer to hold the destination IPv6 address as a string
            // Convert the destination IPv6 address from binary to text form.
            // If inet_ntop fails, log an error, free the packet, and exit processing.
            char dst_ip_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              LOG_MAIN(ERR, "inet_ntop failed for destination address\n");
              rte_pktmbuf_free(mbuf);
              return;
            }

            LOG_MAIN(DEBUG, "Destination IPv6 address: %s\n", dst_ip_str);
            uint8_t hmac_out[HMAC_MAX_LENGTH];
            memcpy(hmac_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);

            // This code decrypts the HMAC in the PoT TLV structure that was encrypted at ingress.
            // First logs the encrypted HMAC length for debugging
            // Then decrypts the Packet Verification Field (PVF) using:
            //  - k_pot_in[0]: Secret key shared between ingress/egress nodes
            //  - pot->nonce: Prevents replay attacks
            //  - hmac_out: Buffer for decrypted result
            // Finally copies the decrypted HMAC back to the PoT structure
            //
            // After this, the code will verify packet integrity by comparing this HMAC
            // with a freshly calculated value to confirm path compliance
            LOG_MAIN(DEBUG, "Encrypted HMAC length: %zu\n", sizeof(pot->encrypted_hmac));
            decrypt_pvf(&k_pot_in[0], pot->nonce, hmac_out);
            memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
            LOG_MAIN(DEBUG, "Decrypted HMAC length: %zu\n", sizeof(pot->encrypted_hmac));

            // Prepare the HMAC key for verification
            // This key is used to calculate the expected HMAC for the packet.
            uint8_t *k_hmac_ie = k_pot_in[0];
            uint8_t expected_hmac[HMAC_MAX_LENGTH];
            LOG_MAIN(DEBUG, "Calculating expected HMAC with key length %zu\n", HMAC_MAX_LENGTH);
            if (calculate_hmac((uint8_t *)&ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, HMAC_MAX_LENGTH,
                               expected_hmac) != 0) {
              LOG_MAIN(ERR, "Egress: HMAC calculation failed\n");
              rte_pktmbuf_free(mbuf);
              return;
            }

            LOG_MAIN(DEBUG, "Comparing calculated HMAC with expected HMAC\n");
            if (memcmp(hmac_out, expected_hmac, HMAC_MAX_LENGTH) != 0) {
              // LOG_MAIN(ERR, "Egress: HMAC verification failed, dropping packet\n");
              rte_pktmbuf_free(mbuf);
              return;
            }

            // If the HMAC verification is successful, we proceed to remove headers
            // and forward the packet to the iperf server.
            // This includes removing the SRH, HMAC TLV, and PoT TLV
            // from the packet, and then sending it to the iperf server.
            // The final packet will have the original IPv6 header and payload,
            // but without the SRH, HMAC TLV, and PoT TLV.
            // LOG_MAIN(INFO, "Egress: HMAC verified successfully, forwarding packet\n");
            remove_headers(mbuf);

            LOG_MAIN(DEBUG, "Packet after removing headers - length: %u\n", rte_pktmbuf_pkt_len(mbuf));
            struct rte_ether_hdr *eth_hdr_final = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            struct rte_ipv6_hdr *ipv6_hdr_final = (struct rte_ipv6_hdr *)(eth_hdr_final + 1);
            LOG_MAIN(DEBUG, "Final packet IPv6 src: %s, dst: %s\n",
                     inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, NULL, 0),
                     inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, NULL, 0));

            char final_src_ip[INET6_ADDRSTRLEN], final_dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, final_src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, final_dst_ip, INET6_ADDRSTRLEN);
            LOG_MAIN(DEBUG, "Final packet IPv6 src: %s, dst: %s\n", final_src_ip, final_dst_ip);

            // Forward the packet to the iperf server
            // The MAC address of the iperf server is hardcoded here.
            struct rte_ether_addr iperf_mac = {{0x02, 0xcc, 0xef, 0x38, 0x4b, 0x25}};
            send_packet_to(iperf_mac, mbuf, 0);
            LOG_MAIN(DEBUG, "Packet sent to iperf server with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                     iperf_mac.addr_bytes[0], iperf_mac.addr_bytes[1], iperf_mac.addr_bytes[2],
                     iperf_mac.addr_bytes[3], iperf_mac.addr_bytes[4], iperf_mac.addr_bytes[5]);
          }
          break;
        }
        case 1:

          LOG_MAIN(DEBUG, "Bypassing all operations for egress packet\n");
          break;

          LOG_MAIN(DEBUG, "Removing headers only for egress packet\n");
        default: break;
      }
      break;
    default: break;
  }
}

void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  // Processes each received packet in the egress queue.
  // This function iterates over the received packets, processes each one,
  // and logs the packet information.
  // It is called by the egress node to handle packets that are ready to be sent
  // out of the egress node.
  // LOG_MAIN(NOTICE, "Processing %u egress packets\n", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    // Skip per-packet logging to reduce spam
    process_egress_packet(pkts[i]);
  }
}
