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

//LAB1
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

    // LAB1: Only use port1
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
		// LAB1: Only use port1
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

	/* Main work of application loop. 8< */
	//LAB1: only loop once
	for (;;) {
		char filename[50];
		struct tm *timenow;
		time_t now = time(NULL);
		timenow = gmtime(&now);
		FILE *fp;

		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {
			// printf("\nLOGGING: Starting port forwarding test [portid=%u]\n", port);
			// LAB1: Only use port1
			if (port != 1) continue;

			// printf("\nLOGGING: Attempt burst of RX packets [portid=%u]\n", port);
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			uint16_t pkt_len;
			// struct rte_mbuf *mbuf;
			struct rte_ether_hdr *ether_hdr;
			struct rte_ipv4_hdr *ipv4_hdr;
			struct rte_icmp_hdr *icmp_hdr;
			struct rte_ether_addr ether_src;
			uint32_t ip_addr_src;
			uint16_t cksum;

			uint16_t pkt_counter = 0;
			while (pkt_counter < nb_rx) {
				//
				pkt_len = rte_pktmbuf_pkt_len(bufs[pkt_counter]);
				//todo: is this needed?
				// mbuf = rte_pktmbuf_mtod(bufs[pkt_counter], struct rte_mbuf *);

				// The function documentation is wrong. Cast type is 2nd parameter, additional offset is 3rd parameter
				ether_hdr = rte_pktmbuf_mtod_offset(bufs[pkt_counter], struct rte_ether_hdr *, 0);
				ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[pkt_counter], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
				icmp_hdr = rte_pktmbuf_mtod_offset(bufs[pkt_counter], struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

				//ether frame
				rte_ether_addr_copy(&ether_hdr->src_addr, &ether_src);
				rte_ether_addr_copy(&ether_hdr->dst_addr, &ether_hdr->src_addr);
				rte_ether_addr_copy(&ether_src, &ether_hdr->dst_addr);

				//ipv4
				ip_addr_src = ipv4_hdr->src_addr;
				ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
				ipv4_hdr->dst_addr = ip_addr_src;

				//icmp
				icmp_hdr->icmp_cksum = 0;
				icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
				//TODO: calculate icmp packet size (data len - headers)
				cksum = rte_raw_cksum(icmp_hdr, 64);
				icmp_hdr->icmp_cksum = (uint16_t)~~cksum;

				strftime(filename, sizeof(filename), "/opt/log/reply_packet_dump_%Y%m%d_%H%M%S", timenow);

				fp = fopen(filename, "w");
				rte_pktmbuf_dump(fp, bufs[pkt_counter], pkt_len);
				printf("\nLOGGING: Packets dumped to file [filename=%s]\n", filename);
				++pkt_counter;
			}
			fclose(fp);


// 			printf("\nLOGGING: Burst of RX packets retrieved [portid=%u, nb_rx=%u]\n", port, nb_rx);
// 			uint16_t data_len = rte_pktmbuf_pkt_len(bufs[0]);
// 			char filename[50];
// 			struct tm *timenow;
// 			time_t now = time(NULL);
// 			timenow = gmtime(&now);

// 			strftime(filename, sizeof(filename), "/opt/log/packet_dump_%Y%m%d_%H%M%S", timenow);

// 			FILE *fp;
// 			fp = fopen(filename, "w");
// 			rte_pktmbuf_dump(fp, bufs[0], data_len);
// 			printf("\nLOGGING: Packets dumped to file [filename=%s]\n", filename);

// 			uint16_t size = sizeof bufs / sizeof *bufs;
			
// 			printf("\nLOGGING: bufs struct array data [bufs_size=%u, bufs0_data_len=%u]\n", size, data_len);
// 			char *data;
// 			char *pointer;
// 			char copy[data_len];
// 			data =  rte_pktmbuf_mtod(bufs[0], char*);
// 			uint16_t counter = 0;
// 			for(pointer = data; pointer < data + data_len; ++pointer) {
// 				printf("\nLOGGING: Data Log [position=%u, char_val=%hhx]\n", counter, *pointer);
// 				copy[counter] = *pointer;
// 				printf("\nLOGGING: Data Log [copy_val=%hhx]\n", copy[counter]);

// 				++counter;
// 				//LAB1: Failsafe
// 				if (counter >= data_len+20) {
// 					printf("\nLOGGING: Failsafe triggered\n");
// 					break;
// 				}
// 			}
// 			//LAB1: Print packet (for hardcoding purposes)
// 			/*
// 			ec:b1:d7:85:6a:13
// 			Captured Packet
// 			14 58 d0 58 
// 			5f 33 ec b1 
// 			d7 85 6a 13 
// 			08 00 45 00 
// 			00 54 7c 5d 
// 			40 00 40 01 
// 			3a f6 c0 a8 
// 			01 02 c0 a8 
// 			01 03 08 00 
// 			2b 83 00 03 
// 			00 01 8a 6e 
// 			25 63 00 00 
// 			00 00 59 d4 
// 			04 00 00 00 
// 			00 00 10 11 
// 			12 13 14 15 
// 			16 17 18 19 
// 			1a 1b 1c 1d 
// 			1e 1f 20 21 
// 			22 23 24 25 
// 			26 27 28 29 
// 			2a 2b 2c 2d 
// 			2e 2f 30 31 
// 			32 33 34 35 
// 			36 37
// ====
// 			14 58 d0 58 
// 			5f 33 ec b1 
// 			d7 85 6a 13 
// 			// addresses^
// 			08 00 45 00 
// 			00 54 2d dd 
// 			40 00 40 01 
// 			89 76 c0 a8 
// 			01 02 c0 a8 
// 			01 03 08 00 
// 			68 43 00 04 
// 			//10^
// 			00 01 89 70 
// 			25 63 00 00 
// 			00 00 1d 11 
// 			05 00 00 00 
// 			00 00 10 11 
// 			12 13 14 15 
// 			16 17 18 19 
// 			1a 1b 1c 1d 
// 			1e 1f 20 21 
// 			22 23 24 25 
// 			26 27 28 29 
// 			2a 2b 2c 2d 
// 			2e 2f 30 31 
// 			32 33 34 35 
// 			36 37 
// 			=======
// 			swapped addresses test
// 			ec b1 d7 85 
// 			6a 13 14 58 
// 			d0 58 5f 33 
// 			08 00 45 00 
// 			00 54 63 ba 
// 			40 00 40 01 
// 			53 99 c0 a8 
// 			01 02 c0 a8 
// 			01 03 08 00 
// 			37 4d 00 05 
// 			00 01 a6 7e 
// 			25 63 00 00 
// 			00 00 33 f8 
// 			02 00 00 00 
// 			00 00 10 11 
// 			12 13 14 15 
// 			16 17 18 19 
// 			1a 1b 1c 1d 
// 			1e 1f 20 21 
// 			22 23 24 25 
// 			26 27 28 29 
// 			2a 2b 2c 2d 
// 			2e 2f 30 31 
// 			32 33 34 35 
// 			36 37

// 			===
// 			swapped addresses packet:
// 			swapped addresses
// 			ec b1 d7 85 
// 			6a 13 14 58 
// 			d0 58 5f 33 
// 			08 00 45 00 
// 			00 54 67 ff 
// 			40 00 40 01 
// 			4f 54 c0 a8 
// 			01 02 c0 a8 
// 			01 03 08 00 
// 			61 76 00 0a 
// 			00 01 d5 2c 
// 			26 63 00 00 
// 			00 00 d2 1b 
// 			0a 00 00 00 
// 			00 00 10 11 
// 			12 13 14 15 
// 			16 17 18 19 
// 			1a 1b 1c 1d 
// 			1e 1f 20 21 
// 			22 23 24 25 
// 			26 27 28 29 
// 			2a 2b 2c 2d 
// 			2e 2f 30 31 
// 			32 33 34 35 
// 			36 37

// 			checksum issues
// 			nochange: 53381 -> D085
// 			fromtype: 20990 -> 51FE
// 			*/
// 			//attempt to use ipv4 helpers
// 			// struct rte_icmp_hdr *icmp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_icmp_hdr*, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
// 			/* Handle IPv4 headers.*/
// 			struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod_offset(bufs[0], struct rte_ether_hdr *, 0);
// 			printf("\nLOGGING: Ether Header check\n");
// 			printf("\nLOGGING: Destination Address\n");
// 			char *prtp = (char *)(&(ether_hdr->dst_addr));
// 			counter = 0;
// 			while (counter < 6) {
// 				printf("%02hhx ", *prtp);
// 				++counter;
// 				if (counter % 4 == 0)
// 					printf("\n");
// 				++prtp;
// 			}

// 			printf("\nLOGGING: Source Address\n");
// 			prtp = (char *)(&(ether_hdr->src_addr));
// 			counter = 0;
// 			while (counter < 6) {
// 				printf("%02hhx ", *prtp);
// 				++counter;
// 				if (counter % 4 == 0)
// 					printf("\n");
// 				++prtp;
// 			}

			
// 			//calculate offset
// 			// printf("\nLOGGING: IPv4 api check [bufs0_ptr=%p, header_ptr=%p, data_ptr=%p]\n", bufs[0], ipv4_hdr, data);
// 			//print checksum from helpers
// 			// printf("\nLOGGING: IPv4 api check [header_checksum=%u]\n", ipv4_hdr->hdr_checksum);
			
// 			//print from bufs[0] to data
// 			// printf("\nLOGGING: BUFS[0] to data\n");
// 			// prtp = (char *)bufs[0];
// 			// counter = 0;
// 			// while (prtp != data) {
// 			// 	printf("%02hhx ", *prtp);
// 			// 	++counter;
// 			// 	if (counter % 4 == 0)
// 			// 		printf("\n");
// 			// 	++prtp;
// 			// }
// 			/*
// 			LOGGING: IPv4 api check [bufs0_ptr=0x100789800, header_ptr=0x10078990e, data_ptr=0x100789900]
// 			LOGGING: IPv4 api check [header_checksum=17297]

// 			LOGGING: BUFS[0] to data
// 			80 98 78 00 
// 			01 00 00 00 
// 			80 98 78 86 
// 			0f 00 00 00 
// 			80 00 01 00 
// 			01 00 01 00 
// 			02 00 00 00 
// 			00 00 00 00 
// 			91 06 00 00 
// 			62 00 00 00 
// 			62 00 00 00 
// 			e2 08 e9 ea 
// 			00 00 00 00 
// 			00 00 80 08 
// 			c0 e4 21 00 
// 			01 00 00 00
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00 
// 			00 00 00 00
// 			*/


// 			//check checksums (shouldn't be needed)
// 			// struct rte_ipv4_hdr *ipv4_hdr_nochange = (struct rte_ipv4_hdr*)data;
// 			// struct rte_ipv4_hdr *ipv4_hdr_fromtype = (struct rte_ipv4_hdr*)(data+sizeof(data[0])*12);
// 			//0 out checksum
// 			// prtp = data+sizeof(data[0])*12;
// 			// counter = 0;
// 			// printf("\nLOGGING: Original checksum\n");
// 			// //TODO: move this to a function for printing data
// 			// for (; counter < 4; ++prtp )
// 			// {
// 			// 	printf("%02hhx ", *prtp);
// 			// 	++counter;
// 			// 	if (counter % 4 == 0)
// 			// 		printf("\n");
// 			// }
// 			// strcpy( data+sizeof(data[0])*14, "\x00\x00");
// 			// prtp = data+sizeof(data[0])*12;
// 			// counter = 0;
// 			// printf("\nLOGGING: Testing checksum manipulation\n");
// 			// //TODO: move this to a function for printing data
// 			// for (; counter < 4; ++prtp )
// 			// {
// 			// 	printf("%02hhx ", *prtp);
// 			// 	++counter;
// 			// 	if (counter % 4 == 0)
// 			// 		printf("\n");
// 			// }

// 			//Calculate checksum with 2 potential starts for the header pointer
// 			// uint16_t cksum;
// 			// cksum = rte_raw_cksum(ipv4_hdr_nochange, rte_ipv4_hdr_len(ipv4_hdr_nochange));
// 			// printf("\nLOGGING: Testing checksum calculation [cksum_nochange=%u]\n", (uint16_t)~cksum);
// 			//Check if the checksum is automatically updated
// 			// prtp = data+sizeof(data[0])*12;
// 			// counter = 0;
// 			// printf("\nLOGGING: Testing checksum manipulation\n");
// 			//TODO: move this to a function for printing data
// 			// for (; counter < 4; ++prtp )
// 			// {
// 			// 	printf("%02hhx ", *prtp);
// 			// 	++counter;
// 			// 	if (counter % 4 == 0)
// 			// 		printf("\n");
// 			// }
// 			//0 out checksum, in case it was manipulated
// 			// strcpy( data+sizeof(data[0])*14, "\x00\x00");
// 			// prtp = data+sizeof(data[0])*12;
// 			// counter = 0;
// 			// printf("\nLOGGING: Testing checksum manipulation\n");
// 			//TODO: move this to a function for printing data
// 			// for (; counter < 4; ++prtp )
// 			// {
// 			// 	printf("%02hhx ", *prtp);
// 			// 	++counter;
// 			// 	if (counter % 4 == 0)
// 			// 		printf("\n");
// 			// }

// 			// cksum = rte_raw_cksum(ipv4_hdr_fromtype, rte_ipv4_hdr_len(ipv4_hdr_fromtype));
// 			struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[0], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
// 			struct rte_icmp_hdr *icmp_hdr = rte_pktmbuf_mtod_offset(bufs[0], struct rte_icmp_hdr*, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
// 			printf("\nLOGGING: Testing checksum calculation [cksum_original=%u]\n", (uint16_t)icmp_hdr->icmp_cksum);
// 			uint16_t cksum_original = (uint16_t)icmp_hdr->icmp_cksum;
// 			printf("\nLOGGING: Testing checksum calculation [cksum_original_copy=%u]\n", cksum_original);
// //operation: 50707
// //original: 50698

// //should be: 50706
// 			icmp_hdr->icmp_cksum = 0;
// 			icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
// 			// uint32_t cksum;
// 			uint16_t cksum = rte_raw_cksum(icmp_hdr, 64);
// 			printf("\nLOGGING: Testing checksum calculation [cksum_updated_helper=%u]\n", (uint16_t)~cksum);

// 			// icmp_hdr->icmp_cksum = cksum_original;
// 			// cksum = ~icmp_hdr->icmp_cksum & 0xffff;
// 			// cksum += ~RTE_BE16(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
// 			// cksum += RTE_BE16(RTE_IP_ICMP_ECHO_REPLY << 8);
// 			// cksum = (cksum & 0xffff) + (cksum >> 16);
// 			// cksum = (cksum & 0xffff) + (cksum >> 16);

// 			// printf("\nLOGGING: Testing checksum calculation [cksum_updated=%u]\n", (uint16_t)~cksum);
// 			// icmp_hdr->icmp_cksum = ~cksum;
// 			uint16_t overflow_diff = 65535-icmp_hdr->icmp_cksum;
// 			if (overflow_diff < 8) {
// 				icmp_hdr->icmp_cksum = 8-overflow_diff;
// 			} else {
// 				icmp_hdr->icmp_cksum = cksum_original+8;
// 			}

// 			//ipv4
// 			uint32_t ip_addr_src = ipv4_hdr->src_addr;
// 			ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
// 			ipv4_hdr->dst_addr = ip_addr_src;

// 			// Address Swap. bufs[0] / data will be mutated. Copy will stay the same
// 			if (data_len == 98) {
// 				memcpy(&data[0], &copy[6], 6 * sizeof(data[0]));
// 				memcpy(&data[6], &copy[0], 6 * sizeof(data[0]));
// 			}
			
// 			printf("\nLOGGING: Confirm swapped addresses\n");
// 			data =  rte_pktmbuf_mtod(bufs[0], char*);
// 			counter = 0;
// 			for(pointer = data; pointer < data + data_len; ++pointer) {
// 				printf("\nLOGGING: Data Log [position=%u, char_val=%hhx]\n", counter, *pointer);

// 				++counter;
// 				//LAB1: Failsafe
// 				if (counter >= data_len+20) {
// 					printf("\nLOGGING: Failsafe triggered\n");
// 					break;
// 				}
// 			}
// 			//Dump to file
// 			// char filename[40];
// 			// struct tm *timenow;
// 			// time_t now = time(NULL);
// 			// timenow = gmtime(&now);

// 			strftime(filename, sizeof(filename), "/opt/log/reply_packet_dump_%Y%m%d_%H%M%S", timenow);

// 			fclose(fp);
// 			fp = fopen(filename, "w");
// 			rte_pktmbuf_dump(fp, bufs[0], data_len);
// 			printf("\nLOGGING: Packets dumped to file [filename=%s]\n", filename);

			// prtp = copy;
			// counter = 0;
			// for (; counter < data_len; ++prtp )
			// {
			// printf("%02hhx ", *prtp);
			// ++counter;
			// if (counter % 4 == 0)
			// 	printf("\n");
			// }
			
			/* Send burst of TX packets, to second port of pair. */
			// const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
			// 		bufs, nb_rx);
			//LAB1:
			// const uint16_t nb_tx = 0;
			const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
					bufs, nb_rx);

			printf("\nLOGGING: Burst of TX packets to second port passed [nb_tx=%u]\n", nb_tx);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
		//LAB1: sleep 3 seconds
		sleep(1);
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
		// LAB1: Only use port1
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
