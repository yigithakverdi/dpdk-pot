#include <rte_dev.h>
#include <sys/types.h>

#include "core/init.h"
#include "core/nodemng.h"
#include "dataplane/forward.h"
#include "dataplane/processing.h"
#include "port.h"
#include "routing/routecontroller.h"
#include "utils/logging.h"

int main(int argc, char *argv[]) {
  printf("Initializing IPv6 to MAC table at startup\n");
  add_next_hop("2a05:d014:dc7:1209:8169:d7d9:3bcb:d2b3", "02:5f:68:c7:cc:cd");
  add_next_hop("2a05:d014:dc7:12dc:9648:6bf3:e182:c7b4", "02:f5:27:51:bc:1d");

  init_eal(argc, argv);

  int log_level = RTE_LOG_INFO;
  int app_arg_start = 1;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--") == 0) {
      app_arg_start = i + 1;
      break;
    }
  }

  for (int i = app_arg_start; i < argc; ++i) {
    if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
      if (strcmp(argv[i + 1], "ingress") == 0)
        global_role = ROLE_INGRESS;
      else if (strcmp(argv[i + 1], "transit") == 0)
        global_role = ROLE_TRANSIT;
      else if (strcmp(argv[i + 1], "egress") == 0)
        global_role = ROLE_EGRESS;
      i++;
    } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
      if (strcmp(argv[i + 1], "debug") == 0)
        log_level = RTE_LOG_DEBUG;
      else if (strcmp(argv[i + 1], "info") == 0)
        log_level = RTE_LOG_INFO;
      else if (strcmp(argv[i + 1], "warning") == 0)
        log_level = RTE_LOG_WARNING;
      else if (strcmp(argv[i + 1], "error") == 0)
        log_level = RTE_LOG_ERR;
      i++;
    }
  }

  init_logging("/var/log/dpdk-pot", "app", log_level);
  check_ports_available();

  struct rte_mempool *mbuf_pool = create_mempool();
  register_tsc_dynfield();

  uint16_t port_id = 0;

  setup_port(port_id, mbuf_pool, 1);
  printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());

  uint16_t nb_ports = rte_eth_dev_count_avail();
  printf(
      "\n==== DPDK Port Information ===="
      "\n");
  printf("DPDK detected %u available port(s):\n", nb_ports);

  for (uint16_t port_id_iter = 0; port_id_iter < nb_ports; port_id_iter++) {
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr mac_addr;
    struct rte_eth_link link;

    rte_eth_dev_info_get(port_id_iter, &dev_info);
    rte_eth_macaddr_get(port_id_iter, &mac_addr);
    rte_eth_link_get_nowait(port_id_iter, &link);

    printf("Port %u:\n", port_id_iter);
    printf("  Device name: %s\n", dev_info.device ? rte_dev_name(dev_info.device) : "N/A");
    printf("  Driver: %s\n", dev_info.driver_name ? dev_info.driver_name : "N/A");
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
           mac_addr.addr_bytes[2], mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    printf("  Link status: %s, Speed: %u Mbps, Duplex: %s\n", link.link_status ? "UP" : "DOWN",
           link.link_speed, link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half");
  }
  printf(
      "==== End DPDK Port Information ===="
      "\n\n");

  uint16_t ports[1] = {port_id};
  printf("Starting %u role on port %u\n", global_role, port_id);
  launch_lcore_forwarding(ports);

  return 0;
}