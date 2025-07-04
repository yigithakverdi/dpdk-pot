#ifndef COMMON_H
#define COMMON_H

// Add these headers
#include <netinet/in.h>      // For in6_addr
#include <rte_ether.h>       // For rte_ether_addr
#include <inttypes.h>        // For PRIu64
#include <string.h>          // For string functions
#include <stddef.h>          // For size_t
#include <stdint.h>          // For uint32_t

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256
#define CUSTOM_HEADER_TYPE 0x0833
#define EXTRA_SPACE 128
#define NONCE_LENGTH 16
#define HMAC_MAX_LENGTH 32
#define SID_NO 4
#define MAX_NEXT_HOPS 8
#define MAX_POT_NODES 50
extern int operation_bypass_bit;
extern int tsc_dynfield_offset;
typedef uint64_t tsc_t;


extern uint8_t k_pot_in[MAX_POT_NODES+1][HMAC_MAX_LENGTH]; // +1 for egress
extern int num_transit_nodes;
     
struct next_hop_entry {
  struct in6_addr ipv6;
  struct rte_ether_addr mac;
};

static struct next_hop_entry next_hops[MAX_NEXT_HOPS];
static int next_hop_count = 0;

struct ipv6_srh {
  uint8_t next_header;   // Next header type
  uint8_t hdr_ext_len;   // Length of SRH in 8-byte units
  uint8_t routing_type;  // Routing type (4 for SRv6)
  uint8_t segments_left;
  uint8_t last_entry;
  uint8_t flags;                // Segments yet to be visited
  uint8_t reserved[2];          // Reserved for future use
  struct in6_addr segments[2];  // Array of IPv6 segments max 10 nodes
};

struct hmac_tlv {
  uint8_t type;            // 1 byte for TLV type
  uint8_t length;          // 1 byte for TLV length
  uint16_t d_flag : 1;     // 1-bit D flag
  uint16_t reserved : 15;  // Remaining 15 bits for reserved
  uint32_t hmac_key_id;    // 4 bytes for the HMAC Key ID
  uint8_t hmac_value[32];  // 8 Octets HMAC value must be multiples of 8 octetx
                           // and ma is 32 octets
};

struct pot_tlv {
  uint8_t type;                // Type field (1 byte)
  uint8_t length;              // Length field (1 byte)
  uint8_t reserved;            // Reserved field (1 byte)
  uint8_t nonce_length;        // Nonce Length field (1 byte)
  uint32_t key_set_id;         // Key Set ID (4 bytes)
  uint8_t nonce[16];           // Nonce (variable length)
  uint8_t encrypted_hmac[32];  // Encrypted HMAC (variable length)
};

#endif  // COMMON_H