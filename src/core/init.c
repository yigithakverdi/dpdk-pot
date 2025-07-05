#include "core/init.h"

#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>
#include <stdlib.h>
#include <stdalign.h>
#include <errno.h>

#include "utils/common.h"
#include "utils/logging.h"

void register_tsc_dynfield() {
  LOG_MAIN(DEBUG, "Registering TSC dynamic field for mbufs\n");
  static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
      .name = "dpdk_pot_dynfield_tsc",
      .size = sizeof(tsc_t),
      .align = alignof(tsc_t),
  };
  LOG_MAIN(DEBUG, "TSC dynamic field size: %zu, align: %zu\n", tsc_dynfield_desc.size,
           tsc_dynfield_desc.align);

  // Register a dynamic field for the Time Stamp Counter (TSC) within DPDK mbufs.
  // This allows storing a TSC value directly in each packet buffer (mbuf)
  // without modifying the core rte_mbuf structure.
  //
  // Check if the registration was successful. If not, terminate the application
  // as the ability to store TSC in mbufs is critical.
  tsc_dynfield_offset = rte_mbuf_dynfield_register(&tsc_dynfield_desc);
  if (tsc_dynfield_offset < 0) rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");
}

void init_eal(int argc, char *argv[]) {
  LOG_MAIN(DEBUG, "Initializing DPDK EAL\n");

  // Initialize the Environment Abstraction Layer (EAL) for DPDK.
  // 'argc' and 'argv' are typically the command-line arguments passed
  // to the main function of the application. The EAL parses these
  // arguments to configure itself (e.g., --lcores, --socket-mem, -c, -n).
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
}

struct rte_mempool *create_mempool() {
  LOG_MAIN(DEBUG, "Creating mbuf pool\n");

  // Create a memory pool (mempool) specifically for DPDK packet buffers (mbufs).
  // This mempool will be used to allocate and free mbufs efficiently during
  // packet reception, transmission, and processing.
  //
  // Arguments to rte_pktmbuf_pool_create():
  // 1. "MBUF_POOL": A human-readable name for the mempool, useful for debugging
  //    and identifying pools in multi-pool scenarios.
  // 2. NUM_MBUFS * rte_eth_dev_count_avail():
  //    - NUM_MBUFS: A macro or constant defining the desired number of mbufs
  //                 per available Ethernet device.
  //    - rte_eth_dev_count_avail(): A DPDK function that returns the number of
  //                                 detected and available Ethernet devices.
  //    The product calculates the total number of mbufs needed, scaled by the
  //    number of network interfaces that will be used. This ensures enough
  //    buffers are pre-allocated for all active ports.
  // 3. MBUF_CACHE_SIZE: The size of the per-core object cache. When an lcore
  //    (logical core) needs an mbuf, it first tries to get it from its local
  //    cache. When it frees an mbuf, it returns it to its local cache. This
  //    reduces contention on the global mempool lock and improves performance.
  //    A value of 0 means no per-core cache is used, which is generally not
  //    recommended for performance-critical applications.
  // 4. 0: This argument is for a private data size. For packet mbufs (pktmbufs),
  //    it's typically set to 0 as the necessary private data is handled by DPDK.
  // 5. RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE: The size of the data buffer
  //    within each mbuf.
  //    - RTE_MBUF_DEFAULT_BUF_SIZE: DPDK's default buffer size, typically large
  //                                 enough for most Ethernet frames (e.g., 2048 bytes).
  //    - EXTRA_SPACE: Additional space to reserve within each mbuf's data buffer.
  //                   This is useful for adding custom metadata, header adjustments,
  //                   or ensuring enough headroom/tailroom for specific protocols
  //                   or operations without reallocating buffers. This extra space
  //                   could be for the dynamic fields mentioned in previous questions,
  //                   or for other application-specific data.
  // 6. rte_socket_id(): The NUMA socket ID where the memory for this mempool
  //    should be allocated. Allocating memory on the same NUMA node as the
  //    CPU cores that will primarily use the mbufs significantly improves
  //    performance by reducing cross-NUMA node memory access latency.
  struct rte_mempool *mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(), MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE, rte_socket_id());

  LOG_MAIN(DEBUG, "Mbuf pool created: %p\n", mbuf_pool);

  // Check if the mempool creation was successful.
  // If rte_pktmbuf_pool_create returns NULL, it indicates a failure (e.g.,
  // insufficient huge page memory, invalid arguments). This is a fatal error
  // for a DPDK application as it cannot process packets without mbufs.
  if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  // Return the pointer to the newly created mbuf pool. This pointer will be
  // used by the application to retrieve mbufs for packet I/O and processing.
  LOG_MAIN(DEBUG, "Mbuf pool created successfully\n");
  return mbuf_pool;
}