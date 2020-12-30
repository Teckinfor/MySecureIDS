#include <stdio.h>
#include "populate.h"

void generate_ip(unsigned int ip, char ip_addr[]){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(ip_addr,IP_ADDR_LEN_STR,
        "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]); 
}

void print_payload(int payload_length, unsigned char *payload){

        if (payload_length > 0){
                const u_char *temp_pointer = payload;
                int byte_count = 0;
                while (byte_count++ < payload_length){

                        if (byte_count%100 == 0){
                                printf("\n");
                        }
                        printf("%c", (char)*temp_pointer);
                        temp_pointer++;
                }
                printf("\n");
        }
}


int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame, int display_all_frames, int count_frame){
        
        if(display_all_frames){
                printf("\n-----New Frame : n°%d-----\n", count_frame);
        }
        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        const struct sniff_udp *udp;
        unsigned char *payload; /* Packet payload */

        u_int size_ip;
        u_int size_tcp;
        u_int size_udp;

        ethernet = (struct sniff_ethernet*)(packet);
        //ETHER_Frame custom_frame;
        char src_mac_address[ETHER_ADDR_LEN_STR];
        char dst_mac_address[ETHER_ADDR_LEN_STR];
        custom_frame->frame_size = header->caplen;
        // Convert unsigned char MAC to string MAC
        for(int x=0;x<6;x++){       
                snprintf(src_mac_address+(x*2),ETHER_ADDR_LEN_STR,
                        "%02x",ethernet->ether_shost[x]);
                snprintf(dst_mac_address+(x*2),ETHER_ADDR_LEN_STR,
                        "%02x",ethernet->ether_dhost[x]);
        }

        strcpy(custom_frame->source_mac,src_mac_address);
        strcpy(custom_frame->destination_mac, dst_mac_address);

        if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP){

                custom_frame->ethernet_type = ARP;
                if(display_all_frames){
                printf("\nARP packet: %d\n",custom_frame->ethernet_type);
                }
        }

        if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
                custom_frame->ethernet_type = IPV4;
                
                if(display_all_frames){
                printf("\nIPV4 packet: %d\n",custom_frame->ethernet_type);
                }
                

                ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
                IP_Packet custom_packet;
                //custom_packet.protocol_ip = 0;
                char src_ip[IP_ADDR_LEN_STR];
                char dst_ip[IP_ADDR_LEN_STR];
                generate_ip(ip->ip_src.s_addr,src_ip);
                generate_ip(ip->ip_dst.s_addr,dst_ip);

                strcpy(custom_packet.source_ip,src_ip);
                strcpy(custom_packet.destination_ip, dst_ip);

                size_ip = IP_HL(ip)*4;

                if(display_all_frames){
                        printf("IP SOURCE : %s\n",inet_ntoa(ip->ip_src));
                        printf("IP DESTINATION : %s\n",inet_ntoa(ip->ip_dst));
                        printf("Time to live : %d\n", (int)ip->ip_ttl);
                }

                if (size_ip < 20){

                        if(display_all_frames){
                                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                        }
                        
                        return ERROR;
                }

                if((int)ip->ip_p==UDP_PROTOCOL){

                        if(display_all_frames){
                                printf("UDP Handling\n");
                        }

                        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
                        UDP_Packet custom_udp;

                        custom_udp.source_port = ntohs(udp->port_src);
                        custom_udp.source_port = ntohs(udp->port_dst);
                        size_udp = (udp->len + 4);
                        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
                        custom_udp.data = payload;
                        
                }
                else if((int)ip->ip_p==TCP_PROTOCOL){
                
                        if(display_all_frames){
                                printf("TCP Handling\n");
                        }
                        custom_packet.protocol_ip = 1;
                        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                        TCP_Segment custom_segment;

                        size_tcp = TH_OFF(tcp)*4;

                        if (size_tcp < 20) {
                                if(display_all_frames){
                                        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                                }
                                return ERROR;
                        }
                        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

                        int payload_length = (header->caplen)-SIZE_ETHERNET-size_ip-size_tcp;
                        custom_segment.source_port = ntohs(tcp->th_sport);
                        custom_segment.destination_port = ntohs(tcp->th_dport);
                        custom_segment.th_flag = (int)tcp->th_flags;
                        custom_segment.sequence_number = tcp->th_seq;
                        custom_segment.data = payload;
                        custom_segment.data_length = payload_length;

                        custom_packet.data = custom_segment;
                        custom_frame->data = custom_packet;

                        if(display_all_frames){
                                printf("%d ---> %d\n",custom_segment.source_port,custom_segment.destination_port);
                        }
                }

                //Save protocol
                if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
                        if((int)ip->ip_p==UDP_PROTOCOL){
                                custom_frame->data.protocol_ip = 2;
                        }
                        else if((int)ip->ip_p==TCP_PROTOCOL){
                                custom_frame->data.protocol_ip = 1;
                        }
                        else{
                                custom_frame->data.protocol_ip = 0;
                        }
                }        
        }       
	return 0;
}

int show_protocol(ETHER_Frame *frame){
        if(frame->ethernet_type == 2054){
                return 5;
                //ARP
        }

        if(frame->data.protocol_ip == 1){ 
                const u_char *temp_pointer = frame->data.data.data;
                if((char)*temp_pointer == 'H'){
                                temp_pointer++;
                        if((char)*temp_pointer == 'T'){
                                temp_pointer++;
                                if((char)*temp_pointer == 'T'){
                                        temp_pointer++;
                                        if((char)*temp_pointer == 'P'){
                                                return 3;
                                                //HTTP
                                
                                        }
                                
                                }
                        }
                        
                }
                else if((char)*temp_pointer == 'G'){
                                temp_pointer++;
                        if((char)*temp_pointer == 'E'){
                                temp_pointer++;
                                if((char)*temp_pointer == 'T'){
                                        temp_pointer++;
                                        if((char)*temp_pointer == ' '){
                                                return 3;
                                                //HTTP
                                
                                        }
                                
                                }
                        }
                        
                }

                else if(frame->data.data.destination_port == 443 || frame->data.data.source_port == 443){
                        return 4;
                        //HTTPS
                }

                return 1;
                //TCP
        }

        if (frame->data.protocol_ip == 2){
                return 2;
                //UDP
        }
        return 0; //Not implemented
}
