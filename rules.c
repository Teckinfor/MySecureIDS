#include "populate.h"

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int count, int print_alert){

    char msg [255];
    char any[IP_ADDR_LEN_STR] = "any";
	for (int i = 0; i<count; i++){
	
        if(strstr(rules_ds->options,"msg") != NULL){

            char save_opt [255];
            strcpy(save_opt, rules_ds[i].options);

            char * pmsg = strstr(save_opt,"msg");
            strtok(pmsg,"\"");

            strcpy(msg, strtok(NULL,"\""));
        }
        else{
            strcpy(msg,"Alert");
        }

        //IF TCP
        if (rules_ds[i].protocol == show_protocol(frame)){
                        
            if(rules_ds[i].protocol == 1 || rules_ds[i].protocol == 3){

                if (rules_ds[i].ip_src == frame->data.source_ip || !strcmp(rules_ds[i].ip_src,any)){      
                        
                    if (rules_ds[i].port_src == frame->data.data.source_port || rules_ds[i].port_src == 0){       

                        if (rules_ds[i].ip_dst == frame->data.destination_ip || !strcmp(rules_ds[i].ip_dst,any)){       

                            if (rules_ds[i].port_dst == frame-> data.data.destination_port || rules_ds[i].port_dst == 0){       
                                
                                if (rules_ds->action == 1){

                                    if(strstr(rules_ds->options,"content") != NULL){
                                        char save_options [255];
                                        strcpy(save_options, rules_ds[i].options);

                                        char * pcontent = strstr(save_options,"content");
                                        strtok(pcontent,"\"");

                                        char * content = strtok(NULL,"\"");

                                        if(strstr((char *)frame->data.data.data,content) != NULL){
                                            if(print_alert){
                                                printf("ALERT : %s\n", msg);
                                            }
                                            openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                            syslog(LOG_INFO, msg);
                                            closelog();
                                        }
                                    }

                                    else {
                                        if(print_alert){
                                            printf("ALERT : %s\n", msg);
                                        }
                                        openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                        syslog(LOG_INFO, msg);
                                        closelog();
                                    }

                                }			
                            }
                        }
                    }
                }
            }

            //IF UDP
            else if(rules_ds[i].protocol == 2){

                if (rules_ds[i].ip_src == frame->data.source_ip || !strcmp(rules_ds[i].ip_src,any)){      
                        
                    if (rules_ds[i].port_src == frame->data.udp_data.source_port || rules_ds[i].port_src == 0){       

                        if (rules_ds[i].ip_dst == frame->data.destination_ip || !strcmp(rules_ds[i].ip_dst,any)){       

                            if (rules_ds[i].port_dst == frame->data.udp_data.destination_port || rules_ds[i].port_dst == 0){       
                                
                                if (rules_ds->action == 1){

                                    if(strstr(rules_ds->options,"content") != NULL){
                                        char save_options [255];
                                        strcpy(save_options, rules_ds[i].options);

                                        char * pcontent = strstr(save_options,"content");
                                        strtok(pcontent,"\"");

                                        char * content = strtok(NULL,"\"");
                                        printf("yo : %s\n", (char*)frame->data.udp_data.data);
                                        if(strstr((char *)frame->data.udp_data.data,content) != NULL){
                                            if(print_alert){
                                                printf("ALERT : %s\n", msg);
                                            }
                                            openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                            syslog(LOG_INFO, msg);
                                            closelog();
                                        }
                                    }

                                    else {
                                        if(print_alert){
                                            printf("ALERT : %s\n", msg);
                                        }
                                        openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                        syslog(LOG_INFO, msg);
                                        closelog();
                                    }
                                }			
                            }
                        }
                    }
                }
            }
        }
    }
}


void read_rules(FILE * file, Rule *rules_ds, int count){
        char rule[MAXLINE];
        char *protocol;
        char* action;

        for(int i = 0; i < count; i++){
                fgets(rule,MAXLINE,file);

                //ACTION
                action = strtok(rule," ");
                if(!strcmp(action,"alert")){
                        rules_ds[i].action = 1;
                }

                //PROTOCOL
                protocol = strtok(NULL," ");
                if(!strcmp(protocol,"tcp")){
                        rules_ds[i].protocol = 1;
                }
                else if(!strcmp(protocol,"udp")){
                        rules_ds[i].protocol = 2;
                }
                else if(!strcmp(protocol,"http")){
                        rules_ds[i].protocol = 3;
                }
                else if(!strcmp(protocol,"https")){
                        rules_ds[i].protocol = 4;
                }
                else if(!strcmp(protocol,"arp")){
                        rules_ds[i].protocol = 5;
                }
                else {
                        rules_ds[i].protocol = 0;
                }

                //IP SOURCE
                char* ip_src = strtok(NULL," ");
                strcpy(rules_ds[i].ip_src,ip_src);

                //PORT SOURCE
                char* port_src_buf = strtok(NULL," ");
                if(!strcmp(port_src_buf,"any")){
                        rules_ds[i].port_src = 0;
                }
                else {
                        char* endptr1;
                        rules_ds[i].port_src = (int)strtol(port_src_buf, &endptr1, 10);
                }

                //DIRECTION (Don't needed)
                strtok(NULL," ");

                //IP DESTINATION
                char* ip_dst = strtok(NULL," ");
                strcpy(rules_ds[i].ip_dst,ip_dst);
                
                //PORT DESTINATION
                char* port_dst_buf = strtok(NULL," ");
                if(!strcmp(port_dst_buf, "any")){
                        rules_ds[i].port_dst = 0;
                }
                else {
                        char* endptr2;
                        rules_ds[i].port_dst = (int)strtol(port_dst_buf, &endptr2, 10);
                }
                
                //OPTIONS
                char* opt = strtok(NULL,")");
                strcpy(rules_ds[i].options,opt);

                //Remove the first character from the options which is "("
                for(int j = 0; j < strlen(rules_ds[i].options); j++){
                        rules_ds[i].options[j] = rules_ds[i].options[j+1];
                }
        }     
}
