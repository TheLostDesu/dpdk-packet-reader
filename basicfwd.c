/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define ETH_LEN 14
#define IP_LEN 4
#define HEAD_CHECSUM_LEN 2
#define PROTOCOL_LEN 1



/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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


void print_info(int pkt_len, uint8_t *info, FILE *fout)
{
    fprintf(fout, "Size of packet:%d bytes", pkt_len); 
    if(pkt_len < ETH_LEN)
    {
        fprintf(fout, "\nUnknown type of packet");
        fprintf(fout, "\n\nData: ");    
        for(int j = 0; j < pkt_len; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
        return;
    }

    fprintf(fout, "\n\nEthernet:");
    for(int j = 0; j < ETH_LEN; ++j)
    {
        fprintf(fout, " %02X", info[j]);
    }
    fprintf(fout, "\nDestination mac:");
    for(int j = 0; j < 6; ++j)
    {
        fprintf(fout, " %02X", info[j]);
    }
    fprintf(fout, "\nSource mac:");
    for(int j = 6; j < 12; ++j)
    {
        fprintf(fout, " %02X", info[j]);
    }
    fprintf(fout, "\nType:");
    for(int j = 12; j < ETH_LEN; ++j)
    {
        fprintf(fout, " %02X", info[j]);
    }

    if(info[ETH_LEN - 2] == 8 && info[ETH_LEN - 1] == 0)
    {
        fprintf(fout, "(IPv4)");
    }
    else
    {
        fprintf(fout, "(Unknown)");
        fprintf(fout, "\n\nData: ");    
        for(int j = ETH_LEN; j < pkt_len; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
        return;
    }
    if(pkt_len < ETH_LEN)
    {
        fprintf(fout, "\nError in packet, data is too small");
        return;
    }
    int ip_header_length = (info[ETH_LEN] & 15) * 4;
    if(pkt_len < ETH_LEN + ip_header_length)
    {
        fprintf(fout, "\nError in packet, data is too small");
        return;
    }


    fprintf(fout, "\n\nIPv4:");
    for(int j = ETH_LEN; j < ETH_LEN + ip_header_length; ++j)
    {
        fprintf(fout, " %02X", info[j]);
    }

    fprintf(fout, "\nVersion: %d", info[ETH_LEN]>>4);
    fprintf(fout, "\nHeader Length: %d", ip_header_length);

    fprintf(fout, "\nSource Address: ");
    for(int j = ETH_LEN + ip_header_length - IP_LEN * 2; j < ETH_LEN + ip_header_length - IP_LEN; ++j)
    {
        fprintf(fout, "%d", info[j]);
        if(j != ETH_LEN + ip_header_length - IP_LEN - 1)
            fprintf(fout, ".");
    }

    fprintf(fout, "\nDestination Address: ");
    for(int j = ETH_LEN + ip_header_length - IP_LEN; j < ETH_LEN + ip_header_length; ++j)
    {
        fprintf(fout, "%d", info[j]);
        if(j < ETH_LEN + ip_header_length - 1)
            fprintf(fout, ".");
    }
    fprintf(fout, "\nHeader Checksum:");
                
    for(int j = ETH_LEN + ip_header_length - IP_LEN * 2 - HEAD_CHECSUM_LEN; j < ETH_LEN + ip_header_length - IP_LEN * 2; ++j)
    {
        fprintf(fout, " %02X", info[j]);
    }
                
    fprintf(fout, "\nProtocol: %02X", info[ETH_LEN + ip_header_length - IP_LEN * 2 - HEAD_CHECSUM_LEN - PROTOCOL_LEN]);

    if(info[ETH_LEN + ip_header_length - IP_LEN * 2 - HEAD_CHECSUM_LEN - PROTOCOL_LEN] == 17)
    {
        fprintf(fout, "(UDP)");

        fprintf(fout, "\n\nUDP:");

        if(pkt_len < ETH_LEN + ip_header_length + 8)
        {
            fprintf(fout, "\nError in packet, data is too small");
            return;
        }

        for(int j = ETH_LEN + ip_header_length; j < ETH_LEN + ip_header_length + 8; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }

        fprintf(fout, "\nSource port: %d", (info[ETH_LEN + ip_header_length] << 8) + info[ETH_LEN + ip_header_length + 1]);
        fprintf(fout, "\nDestination port: %d", (info[ETH_LEN + ip_header_length + 2] << 8) + info[ETH_LEN + ip_header_length + 3]);
        fprintf(fout, "\nLength: %d", (info[ETH_LEN + ip_header_length + 4] << 8) + info[ETH_LEN + ip_header_length + 5]);
        fprintf(fout, "\nChecksum: %02X %02X", info[ETH_LEN + ip_header_length + 6], info[ETH_LEN + ip_header_length + 7]);

        fprintf(fout, "\n\nData: ");    
        for(int j = ETH_LEN + ip_header_length + 8; j < pkt_len; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }

    }

    else if(info[ETH_LEN + ip_header_length - IP_LEN * 2 - HEAD_CHECSUM_LEN - PROTOCOL_LEN] == 6)
    {
        if(pkt_len <= ETH_LEN + ip_header_length + 12)
        {
            fprintf(fout, "\nError in packet, data is too small");
            return;
        }
        unsigned int tcp_header_len = (info[ETH_LEN + ip_header_length + 12] >> 4) * 4;
        if(pkt_len < ETH_LEN + ip_header_length + tcp_header_len)
        {
            fprintf(fout, "\nError in packet, data is too small");
            return;
        }
        fprintf(fout, "(TCP)");

        fprintf(fout, "\n\nTCP:");
        for(int j = ETH_LEN + ip_header_length; j < ETH_LEN + ip_header_length + tcp_header_len; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
        
        fprintf(fout, "\nSource port: %d", (info[ETH_LEN + ip_header_length] << 8) + info[ETH_LEN + ip_header_length + 1]);
        fprintf(fout, "\nDestination port: %d", (info[ETH_LEN + ip_header_length + 2] << 8) + info[ETH_LEN + ip_header_length + 3]);

        fprintf(fout, "\nSequence number:");
        for(int j = ETH_LEN + ip_header_length + 4; j < ETH_LEN + ip_header_length + 8; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
        fprintf(fout, "\nAcknowledgment number:");
        for(int j = ETH_LEN + ip_header_length + 8; j < ETH_LEN + ip_header_length + 12; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }

        fprintf(fout, "\nTCP header length: %d", tcp_header_len);

        fprintf(fout, "\nParams: %02X", info[ETH_LEN + ip_header_length + 13]);


        fprintf(fout, "\nWindow size: %d", info[ETH_LEN + ip_header_length + 14] << 8 + info[ETH_LEN + ip_header_length + 15]);
        fprintf(fout, "\nChecksum:");
        for(int j = ETH_LEN + ip_header_length + 16; j < ETH_LEN + ip_header_length + 18; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
        fprintf(fout, "\nUrgent pointer:");
        for(int j = ETH_LEN + ip_header_length + 18; j < ETH_LEN + ip_header_length + 20; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
        
        fprintf(fout, "\n\nData: ");    
        for(int j = ETH_LEN + ip_header_length + tcp_header_len; j < pkt_len; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
    }
    else
    {
        fprintf(fout, "(Unknown)");
        fprintf(fout, "\n\nData: ");    
        for(int j = ETH_LEN + ip_header_length; j < pkt_len; ++j)
        {
            fprintf(fout, " %02X", info[j]);
        }
    }
}


void end_of_frame(FILE *fout)
{
    fprintf(fout, "\n");
    for(int i = 0; i < 100; ++i)
    {
        fprintf(fout, "-");
    }
    fprintf(fout, "\n");
}



int main(int argc, char *argv[])
{
    FILE *fout = fopen("ans.txt", "w");
    printf("Insert number of frames\n");
    int file_len;
    scanf("%d", &file_len); 

	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled(%d). Only 1 used.\n", rte_lcore_count());


    uint16_t port;
    
    int number_of_frame = 1;
    end_of_frame(fout);
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;

			for(int i = 0; i < nb_rx; ++i)
            {
                int pkt_len = bufs[i]->data_len;
                uint8_t *info = (uint8_t *)rte_pktmbuf_mtod(bufs[i], uint8_t *);
                fprintf(fout, "ID:%d\n", number_of_frame);
                print_info(pkt_len, info, fout);
                end_of_frame(fout);
                if(number_of_frame == file_len)
                {
                    return 0;
                }
                number_of_frame++;
            }

			for (uint16_t buf = 0; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
		}
	}

	rte_eal_cleanup();

	return 0;
}