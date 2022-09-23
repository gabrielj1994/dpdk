/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

//MIT 6.5810 LAB1
#include <unistd.h>
#include <time.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

    //MIT 6.5810 LAB1: Only use port1
	if (port != 1) return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port) {
		// MIT 6.5810 LAB1: Only use port1
		if (port != 1) continue;
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);
	}

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	// MIT 6.5810 LAB1: hard-coded values for ICMP echo request
	const uint16_t request_size = 1;
	char echo_request[] = {0x00, 0xab, 0x78, 0x00,
					0x01, 0x00, 0x00, 0x00,
					0x00, 0xab, 0xf8, 0x7c,
					0x0f, 0x00, 0x00, 0x00,
					0x80, 0x00, 0x01, 0x00,
					0x01, 0x00, 0x01, 0x00,
					0x02, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x91, 0x06, 0x00, 0x00,
					0x62, 0x00, 0x00, 0x00,
					0x62, 0x00, 0x00, 0x00,
					0xe2, 0x08, 0xe9, 0xea,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x80, 0x08,
					0xc0, 0xe4, 0x21, 0x00,
					0x01, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x14, 0x58, 0xd0, 0x58,
					0x9f, 0x93, 0x14, 0x58,
					0xd0, 0x58, 0x5f, 0xb3,
					0x08, 0x00, 0x45, 0x00,
					0x00, 0x54, 0x3f, 0xab,
					0x40, 0x00, 0x40, 0x01,
					0x77, 0xa8, 0xc0, 0xa8,
					0x01, 0x02, 0xc0, 0xa8,
					0x01, 0x03, 0x08, 0x00,
					0x0f, 0xb6, 0x00, 0x18,
					0x00, 0x01, 0x80, 0xdf,
					0x2c, 0x63, 0x00, 0x00,
					0x00, 0x00, 0x71, 0x1b,
					0x0b, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x10, 0x11,
					0x12, 0x13, 0x14, 0x15,
					0x16, 0x17, 0x18, 0x19,
					0x1a, 0x1b, 0x1c, 0x1d,
					0x1e, 0x1f, 0x20, 0x21,
					0x22, 0x23, 0x24, 0x25,
					0x26, 0x27, 0x28, 0x29,
					0x2a, 0x2b, 0x2c, 0x2d,
					0x2e, 0x2f, 0x30, 0x31,
					0x32, 0x33, 0x34, 0x35,
					0x36, 0x37};

	/* Main work of application loop. 8< */
	for (;;) {

		/*
		MIT 6.5810 LAB 1
		Until interrupted, send an ICMP echo request from port 1 to a partner node. 
		Wait for a reply within at least 10 seconds, otherwise time out and try again.
		*/
		RTE_ETH_FOREACH_DEV(port) {
			// MIT 6.5810 LAB 1: Only use port1
			if (port != 1) continue;

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			bufs[0] = malloc(sizeof(echo_request)/sizeof(echo_request[0]));

			//Copy hard-coded ICMP echo request
			memcpy((char *)bufs[0], echo_request, sizeof(echo_request)/sizeof(echo_request[0]));

			// Capture a whole packet
			char *data;
			char *prtp = (char *)bufs[0];
			data =  rte_pktmbuf_mtod(bufs[0], char*);
			uint16_t pkt_len = rte_pktmbuf_pkt_len(bufs[0]);
			printf("\nLOGGING: MBuf Log [pkt_len=%u, data=%p, bufs_0=%p]\n", pkt_len, data, bufs[0]);

			//Sanity check print from bufs[0] to data
			printf("\nLOGGING: BUFS[0] to data\n");
			uint16_t counter = 0;
			while (prtp != data) {
				printf("%02hhx ", *prtp);
				++counter;
				if (counter % 4 == 0)
					printf("\n");
				++prtp;
				if (counter >= sizeof(echo_request)/sizeof(echo_request[0])) {
					printf("\nLOGGING: Failsafe triggered\n");
					break;
				}
			}

			printf("\nLOGGING: Counter log [counter=%u]\n", counter);

			counter = 0;
			for(prtp = data; prtp < data + pkt_len; ++prtp) {
				// printf("\nLOGGING: Data Log [position=%u, char_val=%hhx]\n", counter, *prtp);
				printf("%02hhx", *prtp);
				++counter;
				if (counter % 4 == 0)
					printf("\n");
				//LAB1: Failsafe
				if (counter >= sizeof(echo_request)/sizeof(echo_request[0])) {
					printf("\nLOGGING: Failsafe triggered\n");
					break;
				}
			}
			continue;


			// //print whole packet

			// // uint16_t pkt_len;
			// // struct rte_mbuf *mbuf;
			
			// printf("\nLOGGING: Dummy log [test_0=%u]\n", (uint16_t)sizeof(test[0]));
			// struct rte_ether_hdr *ether_hdr;
			// struct rte_ipv4_hdr *ipv4_hdr;
			// struct rte_icmp_hdr *icmp_hdr;
			// struct rte_ether_addr ether_src;
			// uint32_t ip_addr_src;
			// uint16_t cksum;

			// uint16_t pkt_counter = 0;
			// while (pkt_counter < nb_rx) {
			// 	//
			// 	// pkt_len = rte_pktmbuf_pkt_len(bufs[pkt_counter]);
			// 	//todo: is this needed?
			// 	// mbuf = rte_pktmbuf_mtod(bufs[pkt_counter], struct rte_mbuf *);

			// 	// The function documentation is wrong. Cast type is 2nd parameter, additional offset is 3rd parameter
			// 	ether_hdr = rte_pktmbuf_mtod_offset(bufs[pkt_counter], struct rte_ether_hdr *, 0);
			// 	ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[pkt_counter], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			// 	icmp_hdr = rte_pktmbuf_mtod_offset(bufs[pkt_counter], struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

			// 	//ether frame
			// 	rte_ether_addr_copy(&ether_hdr->src_addr, &ether_src);
			// 	rte_ether_addr_copy(&ether_hdr->dst_addr, &ether_hdr->src_addr);
			// 	rte_ether_addr_copy(&ether_src, &ether_hdr->dst_addr);

			// 	//ipv4
			// 	ip_addr_src = ipv4_hdr->src_addr;
			// 	ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
			// 	ipv4_hdr->dst_addr = ip_addr_src;

			// 	//icmp
			// 	icmp_hdr->icmp_cksum = 0;
			// 	icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
			// 	//TODO: calculate icmp packet size (data len - headers)
			// 	cksum = rte_raw_cksum(icmp_hdr, 64);
			// 	icmp_hdr->icmp_cksum = (uint16_t)~cksum;

			// 	// strftime(filename, sizeof(filename), "/opt/log/reply_packet_dump_%Y%m%d_%H%M%S", timenow);

			// 	// fp = fopen(filename, "w");
			// 	// rte_pktmbuf_dump(fp, bufs[pkt_counter], pkt_len);
			// 	// printf("\nLOGGING: Packets dumped to file [filename=%s]\n", filename);
			// 	++pkt_counter;
			// }
			// fclose(fp);
			
			/* Send ICMP echo request through TX packets. */
			const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
					bufs, request_size);

			uint64_t hz = rte_get_timer_hz(); 
			uint64_t begin = rte_rdtsc_precise(); 
			// Do something
			uint64_t elapsed_cycles;
			uint64_t microseconds = 0;

			/* Free any unsent packets. */
			if (unlikely(nb_tx < request_size)) {
				uint16_t buf;
				for (buf = nb_tx; buf < request_size; buf++)
					rte_pktmbuf_free(bufs[buf]);
			} else {
				while (microseconds < 10000000) {
					const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
					elapsed_cycles = rte_rdtsc_precise() - begin; 
					microseconds = elapsed_cycles * 1000000 / hz;
					if (nb_rx != 0) {
						break;
					} 
				}

				if (microseconds < 10000000) {
					//TODO: output metrics
					printf("\nLOGGING: ICMP Echo Statistics [packets_transmitted=%u, packets_received=%u, time=%lu microseconds]\n", request_size, request_size, microseconds);

				} else {
					printf("\nLOGGING: ICMP Echo request timeout after 10 seconds\n");
				}
			}
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		printf("\nLOGGING: [portid=%u]\n", portid);
		// MIT 6.5810 LAB1: Only use port1
		if (portid != 1) continue;
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	}
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
