/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include <stdlib.h>
#include <string.h>
#define DEBUG 1

struct cache * cache=NULL;
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
    
    if(DEBUG)
        printf("*** -> Received packet of length %d \n",len);
    struct sr_ethernet_hdr* header = (struct sr_ethernet_hdr*)packet;

    
    if(htons(header->ether_type)==ETHERTYPE_IP){
        if(DEBUG)
            printf("*** packet of TYPE IP \n");
        struct sr_if* inter = sr_get_interface(sr, interface);
        sr_handleIPpacket(sr,packet,len,inter,header);
        
    }
    else if(htons(header->ether_type)==ETHERTYPE_ARP){
        if(DEBUG)
            printf("*** packet of TYPE ARP \n");
        struct sr_if* inter = sr_get_interface(sr, interface);
        sr_handleARPpacket(sr,packet,len,inter,header);
    
    }
    
    
}/* end sr_ForwardPacket */
/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
void sr_handleIPpacket(struct sr_instance* sr,
                        uint8_t * packet/* lent */,
                        unsigned int len,
                        struct sr_if* inter,/* lent */
                        struct sr_ethernet_hdr* header)
{

    struct ip * ipheader = ((struct ip*)(packet + sizeof(struct sr_ethernet_hdr)));
    
    if (ipheader->ip_v!=4) {
        printf("ERROR!! IP VERSION IS NOT 4\n");
        return;
    }


//    printf("%d=====\n",cksum((uint16_t*)ipheader,20 ));
    //int temp = ipheader->ip_sum;
    //ipheader->ip_sum = 0;
    uint16_t sum = ip_checksum(ipheader,ipheader->ip_hl * 4);///cksum((uint16_t*)ipheader,20 );
    //ipheader->ip_sum = temp;
    if (sum != 0)
    {
        printf("DISCARD PACKET \n");
        return;
    }
    ipheader->ip_ttl--;
    if (ipheader->ip_ttl==0) {
        printf("DISCARD PACKET, SEND A ICMP MESSAGE\n");
        //TODO: SEND A ICMP MESSAGE
    }
    else{
        ipheader->ip_sum = 0;
        ipheader->ip_sum = ip_checksum(ipheader,20);//maybe better??
        struct sr_rt* temp = sr->routing_table;
//        struct sr_rt* default_route = NULL;
        struct sr_rt* route = NULL;
        while (temp!=NULL) {
            if(DEBUG)
                printf("*** Searching Entry........... \n");
            if ((temp->dest.s_addr & temp->mask.s_addr) == (ipheader->ip_dst.s_addr & temp->mask.s_addr))
            {
                route = temp;
                if(DEBUG)
                    printf("*** ENTRY FOUND!!!!\n");
                break;
            }
            temp = temp->next;
        }

    
    }
    
    
}/* end sr_handleIPpacket */

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void sr_handleARPpacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     struct sr_if* inter,/* lent */
                     struct sr_ethernet_hdr* header)
{

    struct sr_arphdr* arp_header = ((struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr)));
    
    
    if (htons(arp_header->ar_op)==ARP_REQUEST) {
        if(DEBUG)
            printf("*** packet with ARP_REQUEST\n");
        
        
        
//        for (int i = 0; i < ETHER_ADDR_LEN; i++)
//        {
//        if(DEBUG)
//            printf("*** packet with DESTINATION %d\n",header->ether_dhost[i]);
//            rx_e_hdr->ether_shost[i];
//        }
//
//
//        for (int i = 0; i < ETHER_ADDR_LEN; i++)
//        {
//            if(DEBUG)
//                printf("*** packet with SOURCE %d\n",header->ether_shost[i]);
//        }
        memcpy(header->ether_dhost, header->ether_shost, ETHER_ADDR_LEN);
        memcpy(header->ether_shost, inter->addr, ETHER_ADDR_LEN);//uint8_t
        if(DEBUG)
            printf("*** packet SWITCHED============ \n");
        
//        for (int i = 0; i < ETHER_ADDR_LEN; i++)
//        {
//            if(DEBUG)
//                printf("*** packet with DESTINATION %d\n",header->ether_dhost[i]);
//        }
//        for (int i = 0; i < ETHER_ADDR_LEN; i++)
//        {
//            if(DEBUG)
//                printf("*** packet with SOURCE %d\n",header->ether_shost[i]);
//        }
        arp_header->ar_op = htons(ARP_REPLY);
        memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
        memcpy(arp_header->ar_sha, inter->addr, ETHER_ADDR_LEN);
        arp_header->ar_tip = arp_header->ar_sip;
        arp_header->ar_sip = inter->ip;//NOT SURE
        if(DEBUG)
            printf("*** TRYING TO SEND PACKET \n");
        sr_send_packet(sr, ((uint8_t*)(packet)), sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), inter->name);
    }
    
    else if(htons(arp_header->ar_op)==ARP_REPLY){
        
        if(DEBUG)
            printf("*** packet with ARP_REPLY\n");
        if (cache==NULL) {
            addNewCache(arp_header->ar_sip,arp_header->ar_sha);
        }
        
        
    }
    
    
}/* end sr_handleARPpacket */

void addNewCache(uint32_t ip,unsigned char mac[ETHER_ADDR_LEN]){
    struct cache * temp=NULL;
    temp->ipAddress=ip;
    memcpy(temp->macAddress, mac,ETHER_ADDR_LEN);
    
    if (cache) {
        struct cache * walker=cache;
        while (!walker) {
            walker=walker->next;
        }
        walker->next=temp;
    }
    else{
        cache=temp;
    }
}

void printCache(){
    struct cache * walker=cache;
    while (cache) {
        printf("IP: %d\n",walker->ipAddress);
        printf("MAC: ");
        for (int i=0; i<ETHER_ADDR_LEN; i++) {
            printf("%c",walker->macAddress[i]);
        }
        printf("\n");
        walker=walker->next;
    }
}

/*
 **************************************************************************
 Function: ip_sum_calc
 Description: Calculate the 16 bit IP sum.
 ***************************************************************************
 */
uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}/* end ip_checksum */


uint16_t cksum(uint16_t *buf, int count)
{
//    register uint32_t sum = 0;
//    while (count--)
//    {
//        sum += *buf++;
//        if (sum & 0xFFFF0000)
//        {
//            /* carry occurred,
//             so wrap around */
//            sum &= 0xFFFF;
//            sum++;
//        }
//    }
//    return  ~(sum & 0xFFFF);
    register uint32_t sum = 0;

    while (count > 1) {
        sum += *buf++;
        count -= 2;
    }

    if (count > 0)
        sum += *((uint8_t*)buf);

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return(~sum);
}


//uint16_t cksum(uint8_t* hdr, int len)
//{
//    long sum = 0;
//
//    while(len > 1)
//    {
//        sum += *((unsigned short*)hdr);
//        hdr = hdr + 2;
//        if(sum & 0x80000000)
//        {
//            sum = (sum & 0xFFFF) + (sum >> 16);
//        }
//        len -= 2;
//    }
//
//    if(len)
//    {
//        sum += (unsigned short) *(unsigned char *)hdr;
//    }
//
//    while(sum>>16)
//    {
//        sum = (sum & 0xFFFF) + (sum >> 16);
//    }
//
//    return ~sum;
//
//}



