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
#include <unistd.h>


#define DEBUG 1

struct cache * cache=NULL;
struct cachePackets *head=NULL;
unsigned char MAC[ETHER_ADDR_LEN];

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
        struct sr_if * iface = sr->if_list;
        struct sr_if* inter = sr_get_interface(sr, interface);
        struct ip * ipheader = ((struct ip*)(packet + sizeof(struct sr_ethernet_hdr)));
        uint32_t destinationIP = ipheader->ip_dst.s_addr;
        while(iface)
        {
            if(iface->ip == destinationIP )
            {
                printf("\nICMP Packet for Interface ===============================%s\n",iface->name);
                sr_handleICMPpacket(sr,packet,len,inter,header,interface);// Forumlate the ICMP PACKET TO SEND
                return;
            }
            iface = iface->next;
        }
        
        
        sr_handleIPpacket(sr,packet,len,inter,header);
    }
    else if(htons(header->ether_type)==ETHERTYPE_ARP){
        if(DEBUG)
            printf("*** packet of TYPE ARP \n");
        struct sr_if* inter = sr_get_interface(sr, interface);
        sr_handleARPpacket(sr,packet,len,inter,header,interface);
    
    }
    
    
}/* end  */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
void cachePacket(uint8_t *packet, struct sr_ethernet_hdr * header, int len,struct sr_instance* sr,char *inter)
{


        if(DEBUG)
            printf("cachePacket: packet of length %d \n",len);

        struct cachePackets *temp;
        temp=(struct cachePackets*)malloc(sizeof(struct cachePackets));
        temp->packet = (uint8_t*)malloc(sizeof(uint8_t) * len);
        memcpy(temp->packet,packet,(sizeof(uint8_t) * len));
        temp->sr=sr;
        temp->length=len;
        temp->inter=inter;
        temp->next=NULL;
        if (head==NULL) {
            head=temp;
        }
        else{
            struct cachePackets* temp2 = head;
            while (temp2->next!=NULL) {
                temp2=temp2->next;
            }
            temp2->next=temp;
        }
    
}/* end  */
/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
void sr_handleICMPpacket(struct sr_instance* sr,
                       uint8_t * packet/* lent */,
                       unsigned int len,
                       struct sr_if* inter,/* lent */
                       struct sr_ethernet_hdr* header,
                       char* interface){
    
    struct ip * ipheader = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
    struct icmp * icmpHeader=(struct icmp *) (packet + sizeof (struct sr_ethernet_hdr) + sizeof(struct ip));
    uint32_t senderIP = ipheader->ip_src.s_addr;
    uint32_t destinationIP = ipheader->ip_dst.s_addr;
    int length = len - sizeof (struct sr_ethernet_hdr) - sizeof(struct ip);

    if (icmpHeader->type == 8 && ipheader->ip_ttl>1) {
        printf("\nICMP ECHO REQUEST\n ");
        uint8_t  temp[ETHER_ADDR_LEN];
        memcpy(temp, header->ether_dhost, ETHER_ADDR_LEN);

        memcpy(header->ether_dhost, header->ether_shost, ETHER_ADDR_LEN);
        memcpy(header->ether_shost, temp, ETHER_ADDR_LEN);

        header->ether_type = htons(ETHERTYPE_IP);
        ipheader->ip_src.s_addr=destinationIP;
        ipheader->ip_dst.s_addr=senderIP;
        icmpHeader->type=0;
        icmpHeader->sum = 0;
        icmpHeader->sum =cksum((uint8_t *) packet + sizeof (struct sr_ethernet_hdr) + ipheader->ip_hl * 4,length);
        printf("\nSENDING ICMP ECHO REPLY.............\n ");
        sr_send_packet(sr, packet, len, interface);
    }
    else if(ipheader->ip_ttl<=1|| ipheader->ip_p ==IPPROTO_UDP || ipheader->ip_p ==IPPROTO_TCP){
        printf("\nICMP TCP UDP REQUEST\n ");
        return;
    }

    
    
    
    
}/* end sr_handleICMPpacket */

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
    uint32_t senderIP = ipheader->ip_src.s_addr;
    uint32_t destinationIP = ipheader->ip_dst.s_addr;
    struct sr_rt* newInterface;
    newInterface = RoutingTableLookUp(sr,destinationIP);
    bool found=checkCache(destinationIP);
    printf("Handle IP packet \n ");
    
    
    
    if (ipheader->ip_v!=4) {
        printf("ERROR!! IP VERSION IS NOT 4\n");
        return;
    }
    
    uint16_t sum = ip_checksum(ipheader,ipheader->ip_hl * 4);
    
    if (sum != 0)
    {
        printf("DISCARD PACKET \n");
        return;
    }
    if (ipheader->ip_ttl<=1) {
        printf("DISCARD PACKET, SEND A ICMP MESSAGE\n");
        return;
        
        //TODO: SEND A ICMP MESSAGE
    }


    if(found == false)// destinationIP not in cache
    {

        struct sr_rt* doesInterfaceExistForSourceIp = RoutingTableLookUp(sr,senderIP);
        if(doesInterfaceExistForSourceIp != NULL)
        {
            struct sr_rt* gatewayEntry =  sr->routing_table;
            newInterface = gatewayEntry;
            destinationIP = gatewayEntry->gw.s_addr;
            
            if (checkCache(gatewayEntry->gw.s_addr)==true) {
                ForwardPacket(sr,newInterface,header,packet,len,ipheader,getNode(gatewayEntry->gw.s_addr));
                return;
            }
            
        }
        printf("\n WE need to send an ARP Request to%s",inet_ntoa(*(struct in_addr*)(&destinationIP)));
        cachePacket(packet,header,len,sr,newInterface->interface);// Save the packet
        sendARPrequest(sr, destinationIP, newInterface->interface,newInterface);
        return;
        

    }
    if(found != false)
    {
        ForwardPacket(sr,newInterface,header,packet,len,ipheader,getNode(destinationIP));
        return;
    }
    
}/* end sr_handleIPpacket */



/*
 **************************************************************************
 Function: ForwardPacket
 Description: ForwardPacket
 ***************************************************************************
 */
void ForwardPacket(struct sr_instance * sr,struct sr_rt* newInterface,struct sr_ethernet_hdr * header,uint8_t * packet,unsigned int len,struct ip * ipheader, struct cache * node){
    
    for(int i=0;i<ETHER_ADDR_LEN;i++)
    {
        header->ether_dhost[i] =  (uint8_t)(node->macAddress[i]);
    }
    
    ipheader->ip_ttl = ipheader->ip_ttl -1 ;
    ipheader->ip_sum=0;
    ipheader->ip_sum=cksum(((uint8_t*)(ipheader)),sizeof(struct ip));
    struct sr_if * iface = sr->if_list;
    while (iface)
    {
        if (strcmp(iface->name,newInterface->interface) == 0)
        {
            for(int i=0;i<ETHER_ADDR_LEN;i++)
            {
                header->ether_shost[i] = iface->addr[i];
                
            }
        }
        iface = iface->next;
    }
    printf("\n=================Sending the Packet !!!!!!================\n");
    sr_send_packet(sr,packet,len,newInterface->interface);
}/* end ForwardPacket */


/*
 **************************************************************************
 Function: sendARPrequest
 Description: send ARP request
 ***************************************************************************
 */
void sendARPrequest(struct sr_instance * sr, uint32_t destinationIP, char* interface,struct sr_rt* newInterface)
{
    printf("\nSending ARP Request \n");
    
    uint8_t * packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    
    struct sr_if * inter = sr->if_list;
    struct sr_ethernet_hdr * header = (struct sr_ethernet_hdr *) packet;
    struct sr_arphdr * ARPheader = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));
    

    
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        header->ether_dhost[i] = 255;
    }
//    for (int i = 0; i < ETHER_ADDR_LEN; i++)
//    {
//        header->ether_shost[i] = ((uint8_t)(rx_if->addr[i]));
//    }
    header->ether_type = htons(ETHERTYPE_ARP);
    
    ARPheader->ar_hrd = ntohs(1);

    ARPheader->ar_op = ntohs(ARP_REQUEST);
    ARPheader->ar_pro = ntohs(ETHERTYPE_IP);
    ARPheader->ar_pln = 4;
    ARPheader->ar_hln = 6;
    ARPheader->ar_tip = destinationIP;
    
    while (inter)
    {
        if (strcmp(inter->name,newInterface->interface) == 0)
        {
            for (int i = 0; i < ETHER_ADDR_LEN; i++)
            {
                ARPheader->ar_sha[i] = inter->addr[i];
                header->ether_shost[i] = ARPheader->ar_sha[i];
            }
            ARPheader->ar_sip = inter->ip;
            sr_send_packet(sr, packet, sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr), inter->name);
        }
        inter = inter->next;
    }

}/* end sendARPrequest */


/*
 **************************************************************************
 Function: RoutingTableLookUp
 Description: look up in routing table
 ***************************************************************************
 */

struct sr_rt* RoutingTableLookUp(struct sr_instance* sr,uint32_t ipTarget)
{
    struct sr_rt* temp = sr->routing_table;
//    struct sr_rt* route = NULL;
//    struct sr_rt* default_route = NULL;
    while (temp!=NULL) {
        if(DEBUG)
            printf("*** Searching Entry........... \n");

        if( temp->gw.s_addr ==0 && temp->mask.s_addr > 0 && (temp->mask.s_addr & ipTarget) == temp->dest.s_addr)
        {
            printf("Found InterFace  %s\n",temp->interface);
            return temp;
        }
        temp = temp->next;
    }
    return temp;
}/* end RoutingTableLookUp */

/*
 **************************************************************************
 Function: isGateway
 Description: look up in routing table
 ***************************************************************************
 */
bool isGateway(uint32_t ipTarget, struct sr_instance* sr)
{
    struct sr_rt* routing_table =sr->routing_table;
    while(routing_table != NULL)
    {
        if(routing_table->gw.s_addr == ipTarget)
        {
            return true;
        }
        routing_table = routing_table->next;
        
    }
    return false;
    
}/* end isGateway */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void sr_handleARPpacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     struct sr_if* inter,/* lent */
                     struct sr_ethernet_hdr* header,
                    char* interface
                        )
{

    struct sr_arphdr* arp_header = ((struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr)));
    
    if (htons(arp_header->ar_op)==ARP_REQUEST) {
        if(DEBUG)
            printf("*** packet with ARP_REQUEST\n");
        addNewCache(arp_header->ar_sip,arp_header->ar_sha);
        memcpy(header->ether_dhost, header->ether_shost, ETHER_ADDR_LEN);
        memcpy(header->ether_shost, inter->addr, ETHER_ADDR_LEN);
        if(DEBUG)
            printf("*** packet SWITCHED============ \n");
//
////        for (int i = 0; i < ETHER_ADDR_LEN; i++)
////        {
////            if(DEBUG)
////                printf("*** packet with DESTINATION %d\n",header->ether_dhost[i]);
////        }
////        for (int i = 0; i < ETHER_ADDR_LEN; i++)
////        {
////            if(DEBUG)
////                printf("*** packet with SOURCE %d\n",header->ether_shost[i]);
////        }
        arp_header->ar_op = htons(ARP_REPLY);
        memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
        memcpy(arp_header->ar_sha, inter->addr, ETHER_ADDR_LEN);
        uint32_t tmp = arp_header->ar_tip;
        arp_header->ar_tip = arp_header->ar_sip;
        arp_header->ar_sip = tmp;//NOT SURE
        if(DEBUG)
            printf("*** TRYING TO SEND PACKET \n");
        sr_send_packet(sr, ((uint8_t*)(packet)),len, inter->name);
    }
    
    else if(htons(arp_header->ar_op)==ARP_REPLY){
        
        if(DEBUG)
            printf("*** packet with ARP_REPLY\n");
        addNewCache(arp_header->ar_sip,arp_header->ar_sha);
        sendCachedPacket(arp_header->ar_sip);
    }
    
    
}/* end sr_handleARPpacket */


/*
 **************************************************************************
 Function: sendCachedPacket
 Description: send packet cached
 ***************************************************************************
 */
void sendCachedPacket(uint32_t ip_addr)
{
    printf("\n Sending the Cached Packet\n");
    struct cachePackets* previous = NULL;
    struct cachePackets* current = head;
    struct cachePackets* target = NULL;
    
    while(current != NULL)
    {
        printf(" YES WE HAVE A PACKAGE");
        uint8_t* packet = current->packet;
        struct ip* ipHeader = (struct ip *) (packet + sizeof (struct sr_ethernet_hdr));
        uint32_t destinationIP = ipHeader->ip_dst.s_addr;
        if( (ipHeader->ip_ttl > 1 && ip_addr == destinationIP) || (ipHeader->ip_ttl > 1 && isGateway(ip_addr,current->sr)==true))
        {
            if(previous == NULL)
            {
                target = current;
                current = current->next;
                head = current;
            }
            else
            {
                target = current;
                previous->next = current->next;
                current = current->next;
                
            }
            //struct sr_rt* newInterface = RoutingTableLookUp(target->sr,destinationIP);
            struct sr_ethernet_hdr * header = (struct sr_ethernet_hdr *) target->packet;
            printf(" Sending Cached packet \n");
            sr_handleIPpacket(target->sr,target->packet,target->length,NULL,header);
            printf(" Done sending Cached packet \n");
            free(target);
            
        }
        else
        {
            previous = current;
            current = current->next;
        }
        
    }
}/* end sendCachedPacket */



/*
 **************************************************************************
 Function: addNewCache
 Description: add new cache
 ***************************************************************************
 */

void addNewCache(uint32_t ip,unsigned char mac[ETHER_ADDR_LEN]){

    if(checkCache(ip)==true){
        if(DEBUG)
            printf("*** Alredy in Cache\n");
        return;
    }
    if(DEBUG)
        printf("*** Inserting in Cache\n");
    struct cache * temp=(struct cache*) malloc(sizeof(struct cache));
    temp->ipAddress=ip;
    memcpy(temp->macAddress,mac,ETHER_ADDR_LEN);
    temp->next=NULL;
    if (cache) {
        struct cache * walker=cache;
        while (walker->next != NULL) {
            walker=walker->next;
        }
        walker->next=temp;
    }
    else{
        cache=temp;
    }
}/* end addNewCache */

/*
 **************************************************************************
 Function: printCache
 Description: print all cache just for debbuging
 ***************************************************************************
 */
void printCache(){
    struct cache * walker=cache;
    while (walker) {
        printf("IP: %d\n",walker->ipAddress);
        printf("MAC: ");
        for (int i=0; i<ETHER_ADDR_LEN; i++) {
            printf("%x",walker->macAddress[i]);
        }
        printf("============\n");
        walker=walker->next;
    }
}/* end printCache */


/*
 **************************************************************************
 Function: checkCache
 Description: check if present in cache
 ***************************************************************************
 */
bool checkCache(uint32_t ip){
    struct cache * walker=cache;
    while(walker){
        if (walker->ipAddress==ip) {
            ////MAYBE REMOVE IT OR CHANGE IT?????????? not sure
            memset(MAC, '\0', sizeof(MAC));
            memcpy(MAC, walker->macAddress, ETHER_ADDR_LEN);
            if(DEBUG)
                printf("checkCache:found in Cache\n");
                return true;

        }
        walker=walker->next;
    }
    if(DEBUG)
        printf("checkCache:NOT found in Cache\n");
    return false;
}/* end checkCache */

/*
 **************************************************************************
 Function: getNode
 Description: getNode
 ***************************************************************************
 */
struct cache * getNode(uint32_t ip){
    
    struct cache * walker=cache;
    while(walker){
        if (walker->ipAddress==ip) {
            
            if(DEBUG)
                printf("getNode:return Node \n");
            return walker;
            
        }
        walker=walker->next;
    }
    if(DEBUG)
        printf("getNode:ERROR I didn't find anynode, but I was supposed to find it!!!!!!!\n");
    return NULL;
    
    
}/* end getNode */

/*
 **************************************************************************
 Function: ip_sum_calc
 Description: check the 16 bit IP sum.
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

/*
 **************************************************************************
 Function: setChecksum
 Description: Calculate the 16 bit IP sum.
 ***************************************************************************
 */
uint16_t cksum(uint8_t* hdr, int len)
{
    long sum = 0;
    
    while(len > 1)
    {
        sum += *((unsigned short*)hdr);
        hdr = hdr + 2;
        if(sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }
    
    if(len)
    {
        sum += (unsigned short) *(unsigned char *)hdr;
    }
    
    while(sum>>16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}/* end ip_checksum */




