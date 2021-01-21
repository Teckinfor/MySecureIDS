#include "populate.h"

int show_protocol(ETHER_Frame *frame){
        if(frame->ethernet_type == ARP){
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

                else if(frame->data.data.destination_port == 20 || frame->data.data.source_port == 20 || frame->data.data.destination_port == 21 || frame->data.data.source_port == 21){
                        return 6;
                        //FTP
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
