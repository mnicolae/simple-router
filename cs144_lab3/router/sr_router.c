/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("** -> Received packet of length %d. Print ethernet header.\n", len);
  print_hdr_eth(packet);

  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }
}/* end sr_ForwardPacket */

/* Send all outstanding packets for the given ARP request entry.
   Helper function for ARP reply processing code. */ 
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);
   
     print_hdrs(copyPacket, currPacket->len); 
     sr_send_packet(sr, copyPacket, currPacket->len, iface);
     currPacket = currPacket->next;
  }
}

/* Send an ARP request. */
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip) {
    printf("$$$ -> Send ARP request.\n");

    int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *arpPacket = malloc(arpPacketLen);

    sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) arpPacket;
    memcpy(ethHdr->ether_dhost, generate_ethernet_addr(255), ETHER_ADDR_LEN);

    struct sr_if *currIf = sr->if_list;
    uint8_t *copyPacket;
    while (currIf != NULL) {
        printf("$$$$ -> Send ARP request from interface %s.\n", currIf->name);

        memcpy(ethHdr->ether_shost, (uint8_t *) currIf->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_arp);

        sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (arpPacket + sizeof(sr_ethernet_hdr_t));
        arpHdr->ar_hrd = htons(1);
        arpHdr->ar_pro = htons(2048);
        arpHdr->ar_hln = 6;
        arpHdr->ar_pln = 4;
        arpHdr->ar_op = htons(arp_op_request);
        memcpy(arpHdr->ar_sha, currIf->addr, ETHER_ADDR_LEN);
        memcpy(arpHdr->ar_tha, (char *) generate_ethernet_addr(0), ETHER_ADDR_LEN);
        arpHdr->ar_sip = currIf->ip;
        arpHdr->ar_tip = ip; 

        copyPacket = malloc(arpPacketLen);
        memcpy(copyPacket, ethHdr, arpPacketLen);
        print_hdrs(copyPacket, arpPacketLen);
        sr_send_packet(sr, copyPacket, arpPacketLen, currIf->name);

        currIf = currIf->next;
    }
    printf("$$$ -> Send ARP request processing complete.\n");
}

/* Send an ICMP error. */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

    printf("### -> Send ICMP error.\n");
    /* packet initialization */
    int icmpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *packet = malloc(icmpPacketLen);

    /* packet headers */
    sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp3Hdr = (sr_icmp_t3_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* initialize ethernet header */
    ethHdr->ether_type = htons(ethertype_ip);

    /* initialize IP header */
    ipHdr->ip_hl = 5;
    ipHdr->ip_v = 4;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(icmpPacketLen - sizeof(sr_ethernet_hdr_t));
    ipHdr->ip_id = htons(0);
    ipHdr->ip_off = htons(IP_DF);
    ipHdr->ip_ttl = 64;
    ipHdr->ip_p = ip_protocol_icmp;
    ipHdr->ip_dst = ipDst;

    /* initialize ICMP header */
    icmp3Hdr->icmp_type = type;
    icmp3Hdr->icmp_code = code;
    
    memcpy(icmp3Hdr->data, ipPacket, ICMP_DATA_SIZE);
    icmp3Hdr->icmp_sum = icmp3_cksum(icmp3Hdr, sizeof(sr_icmp_t3_hdr_t)); /* calculate checksum */

    printf("### -> Check routing table, perform LPM.\n");
    struct sr_rt *lpmEntry = sr_get_lpm_entry(sr->routing_table, ipDst);
    if (lpmEntry != NULL) {
        printf("#### -> Match found in routing table. Check ARP cache.\n");

        uint32_t nextHopIP = (uint32_t) lpmEntry->gw.s_addr;
        struct sr_if *interface = sr_get_interface(sr, lpmEntry->interface);

        ipHdr->ip_src = interface->ip;
        ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

        memcpy(ethHdr->ether_shost, (uint8_t *) interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), nextHopIP);
        if (arpEntry != NULL) {
            printf("##### -> Next-hop-IP to MAC mapping found in ARP cache. Forward packet to next hop.\n");

            memcpy(ethHdr->ether_dhost, (uint8_t *) arpEntry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
            print_hdrs(packet, icmpPacketLen);
            sr_send_packet(sr, packet, icmpPacketLen, interface->name);
        } else {
            printf("##### -> No next-hop-IP to MAC mapping found in ARP cache. Send ARP request to find it.\n");
            struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache), 
                                                         nextHopIP,
                                                         packet,
                                                         icmpPacketLen,
                                                         &(interface->name));
            handle_arpreq(sr, arpReq);
        }
    }
    printf("###### -> Send ICMP error processing complete.\n");
}

void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,   
        sr_ethernet_hdr_t *eHdr) {

  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* "refresh" the ARP cache entry associated with sender IP address
     if such an entry already exists. */
  int update_flag = sr_arpcache_entry_update(&(sr->cache), senderIP); 

  /* check if the ARP packet is for one of my interfaces. */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP); 

  if (op == arp_op_request) {
    printf("**** -> It is an ARP request.\n");

    if (myInterface != 0) {
      printf("***** -> ARP request is for one of my interfaces.\n");

      if (update_flag == 0) {
        printf("****** -> Add MAC->IP mapping of sender to my ARP cache.\n");

        /* Note: will take care of the entry in the ARP request queue in
                 the ARP reply processing code. */
        sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
      }

      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *) myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN); 
      memcpy(eHdr->ether_dhost, (uint8_t *) senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);

      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP; 
      arpHdr->ar_op = htons(arp_op_reply);
      print_hdrs(packet, len);
      sr_send_packet(sr, packet, len, myInterface->name);
    }
    printf("******* -> ARP request processing complete.\n");
  } else if (op == arp_op_reply) {
    printf("**** -> It is an ARP reply.\n");
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");

    if (update_flag == 0) {
      struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
      if (arpReq != NULL) {
        printf("****** -> Send outstanding packets.\n");
        sr_arp_reply_send_pending_packets(sr,
                                    arpReq,
                                    (uint8_t *) myInterface->addr,
                                    (uint8_t *) senderHardAddr,
                                    myInterface);   
        sr_arpreq_destroy(&(sr->cache), arpReq);
      } 
    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,   
        sr_ethernet_hdr_t *eHdr) {

  printf("*** -> It is an IP packet. Print IP header.\n");
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_ip_hdr *ipHdr = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

  uint8_t ipProtocol = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ipDst = ipHdr->ip_dst;
  uint32_t ipSrc = ipHdr->ip_src;

  struct sr_if *myInterface = sr_get_interface_given_ip(sr, ipDst); 
  struct sr_rt *lpmEntry = sr_get_lpm_entry(sr->routing_table, ipDst);             

  if (myInterface == NULL && lpmEntry == NULL) {
    printf("*** -> Packet is not for one of my interfaces and no match found in routing table. Send ICMP net unreachable.\n");
    sr_send_icmp_error_packet(3, 0, sr, ipSrc, (uint8_t*)ipHdr);
  } else {
    switch_route(sr, packet, len, srcAddr, destAddr, interface, eHdr, ipHdr, lpmEntry);
  }
}

int is_icmp_echo_request(sr_icmp_hdr_t *icmpHdr) {
  return (icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0) ? 1 : 0;
}

int is_icmp_echo_reply(sr_icmp_hdr_t *icmpHdr) {
 return (icmpHdr->icmp_type == 0 && icmpHdr->icmp_code == 0) ? 1 : 0;
}

/* Return an icmp echo reply message where the packet
   is the icmp echo request.
 */
void icmp_direct_echo_reply(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr,
        sr_ip_hdr_t *ipHdr,
        sr_icmp_hdr_t *icmpHdr) {

  int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

  /* We don't have to look up the routing table for this one */
  struct sr_if *myInterface = sr_get_interface(sr, interface);

  icmpHdr->icmp_type = 0;
  icmpHdr->icmp_code = 0;
  icmpHdr->icmp_sum = icmp_cksum(icmpHdr, len - icmpOffset);

  ipHdr->ip_dst = ipHdr->ip_src;
  ipHdr->ip_src = myInterface->ip;
  ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

  memcpy(eHdr->ether_dhost, srcAddr, sizeof(uint8_t) * ETHER_ADDR_LEN); 
  memcpy(eHdr->ether_shost, destAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, interface);
}

/* Normal Mode IP */
void switch_route(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr,
        sr_ip_hdr_t *ipHdr,
        struct sr_rt *lpmEntry) {

  uint8_t ipProtocol = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ipDst = ipHdr->ip_dst;
  uint32_t ipSrc = ipHdr->ip_src;

  struct sr_if *myInterface = sr_get_interface_given_ip(sr, ipDst); 
  
  if (myInterface == NULL) {
    printf("***** -> IP packet is not for one of my interfaces.\n");
    
    ipHdr->ip_ttl--; /* decrement TTL count. */
    if (ipHdr->ip_ttl <= 0) {
      printf("****** -> TTL field is now 0. Send time exceeded.\n");
      sr_send_icmp_error_packet(11, 0, sr, ipSrc, (uint8_t*) ipHdr);
    } else {
      ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t)); /* recompute checksum */            
      
      uint32_t nextHopIP = (uint32_t) lpmEntry->gw.s_addr;
      struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache, nextHopIP);

      if (arpEntry) {
        printf("******** -> Next-hop-IP to MAC mapping found in ARP cache. Forward packet to next hop.\n");

        struct sr_if *outInterface = sr_get_interface(sr, (const char *) (lpmEntry->interface));

        memcpy(eHdr->ether_dhost, arpEntry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(eHdr->ether_shost, (uint8_t *) outInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

        print_hdrs(packet, len);
        sr_send_packet(sr, packet, len, outInterface); 
      } else {
        printf("******** -> No next-hop-IP to MAC mapping found in ARP cache. Send ARP request to find it.\n");

        struct sr_arpreq *nextHopIPArpReq = sr_arpcache_queuereq(&(sr->cache), nextHopIP, packet, len, &(lpmEntry->interface));
        handle_arpreq(sr, nextHopIPArpReq);
      }
    }
  } else {
    printf("***** -> IP packet is for one of my interfaces.\n");

    if (ipProtocol == ip_protocol_icmp) {
      printf("****** -> It is an ICMP packet. Print ICMP header.\n");

      int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
      print_hdr_icmp(packet + icmpOffset);

      sr_icmp_hdr_t * icmpHdr = (sr_icmp_hdr_t *) (packet + icmpOffset);

      if (is_icmp_echo_request(icmpHdr)) {
        printf("******** -> It is an ICMP echo request. Send ICMP echo reply.\n");
        icmp_direct_echo_reply(sr, packet, len, srcAddr, destAddr, interface, eHdr, ipHdr, icmpHdr);
        printf("********* -> ICMP echo request processing complete.\n");
      }
    } else {
      printf("****** -> IP packet is not an ICMP packet. Send ICMP port unreachable.\n");
      sr_send_icmp_error_packet(3, 3, sr, ipSrc, (uint8_t*) ipHdr);
    }

  printf("********* -> IP packet processing complete.\n");
  }
}