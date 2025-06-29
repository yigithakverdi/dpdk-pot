#include "node/ingress.h"

#include "dataplane/forward.h"
#include "dataplane/headers.h"
#include "dataplane/processing.h"
#include "routing/routecontroller.h"
#include "security/crypto.h"
#include "utils/common.h"
#include "utils/logging.h"

static inline void process_ingress_packet(struct rte_mbuf *mbuf, uint16_t rx_port_id) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // If the packet is not IPv6, free it and return.
  // This is an optimization to quickly discard irrelevant packets.
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(NOTICE, "Non-IPv6 packet received (EtherType: %u), dropping.\n", ether_type);
    rte_pktmbuf_free(mbuf);
    return;
  }

  // Check if the destination MAC address is a multicast/broadcast address.
  // If the least significant bit of the first byte is set, it's multicast/broadcast.
  // Such packets are not processed by this specific logic and are dropped.
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    // LOG_MAIN(NOTICE, "Multicast/Broadcast packet received, dropping.");
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      LOG_MAIN(DEBUG, "Ingress packet is IPv6, processing headers.\n");

      // Control flow based on a global configuration bit.
      // This allows bypassing certain operations for testing or specific use cases.
      LOG_MAIN(DEBUG, "Operation bypass bit is %d\n", operation_bypass_bit);
      switch (operation_bypass_bit) {
        // Case 0: Full processing including custom header addition, HMAC calculation, and
        // encryption.
        case 0:
          LOG_MAIN(DEBUG, "Processing packet with SRH and HMAC for ingress.\n");

          add_custom_header(mbuf);
          struct rte_ether_hdr *eth_hdr6 = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr6 + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          char dst_ip_str[INET6_ADDRSTRLEN];

          if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
            LOG_MAIN(ERR, "inet_ntop failed for destination address.\n");
            perror("inet_ntop failed");
            break;
          }
          LOG_MAIN(DEBUG, "Packet Destination IPv6: %s\n", dst_ip_str);

          uint8_t *k_hmac_ie = k_pot_in[0];
          size_t key_len = HMAC_MAX_LENGTH;

          struct in6_addr ingress_addr;
          inet_pton(AF_INET6, "2a05:d014:dc7:127a:fe22:97ab:a0a8:ff18", &ingress_addr);

          size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
          if (dump_len > 128) dump_len = 128;
          LOG_MAIN(DEBUG, "Packet length for dump: %zu\n", dump_len);

          uint8_t hmac_out[HMAC_MAX_LENGTH];

          // Calculate the HMAC for the packet.
          // This HMAC is computed over specific packet fields (source address, SRH, HMAC TLV, etc.)
          // using the ingress_addr and the HMAC key.
          if (calculate_hmac((uint8_t *)&ingress_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0) {
            rte_memcpy(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH);
            LOG_MAIN(DEBUG, "HMAC calculated and copied to packet.\n");
          } else {
            LOG_MAIN(ERR, "HMAC calculation failed for ingress packet, dropping.\n");
            break;
          }

          uint8_t nonce[NONCE_LENGTH];

          if (generate_nonce(nonce) != 0) {
            LOG_MAIN(ERR, "Nonce generation failed, dropping packet.\n");
            break;
          }

          encrypt_pvf(k_pot_in, nonce, hmac_out);
          rte_memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
          rte_memcpy(pot->nonce, nonce, NONCE_LENGTH);
          LOG_MAIN(DEBUG, "HMAC encrypted and Nonce added to POT TLV.\n");

          if (srh->segments_left == 0) {
            LOG_MAIN(DEBUG, "SRH segments_left is 0, dropping packet.\n");
            rte_pktmbuf_free(mbuf);
          } else {
            // If segments_left is not 0, the packet needs to be forwarded to the next segment ID.
            // Calculate the index of the next segment ID (SID) in the SRH segment list.
            // srh->last_entry is the total number of segments.
            // srh->segments_left is the number of remaining segments to visit.
            // The next SID is (last_entry - segments_left + 1) index into the segments array.
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(struct in6_addr));
            LOG_MAIN(DEBUG, "Updated packet destination to next SID: %s\n",
                     inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)));

            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {
              send_packet_to(*next_mac, mbuf, rx_port_id);
              LOG_MAIN(DEBUG, "Packet sent to next hop with MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       next_mac->addr_bytes[0], next_mac->addr_bytes[1], next_mac->addr_bytes[2],
                       next_mac->addr_bytes[3], next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
            } else {
              LOG_MAIN(ERR, "No MAC found for next SID, dropping packet.\n");
              rte_pktmbuf_free(mbuf);
            }
          }

          break;
        case 1:

          // Case 1: Bypass all custom header operations.
          // The packet is not modified by this function and will proceed
          // to subsequent processing stages (or be forwarded as-is) without
          // SRH/HMAC/POT functionality.
          LOG_MAIN(DEBUG, "Bypassing custom header operations for ingress packet.\n");
          break;

        default: LOG_MAIN(WARNING, "Unknown operation_bypass_bit value: %d\n", operation_bypass_bit); break;
      }
      break;
    default:
      LOG_MAIN(DEBUG,
               "Packet is not IPv6, not processed by ingress_packet_process. This should not be reached.\n");
      break;
  }
}

void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t rx_port_id) {
  // Process each received packet in the ingress queue.
  // This function iterates over the received packets, processes each one,
  // and logs the packet information.
  // LOG_MAIN(NOTICE, "Processing %u ingress packets on port %u", nb_rx, rx_port_id);
  for (uint16_t i = 0; i < nb_rx; i++) {
    // Skip per-packet logging to reduce spam
    process_ingress_packet(pkts[i], rx_port_id);
  }
}