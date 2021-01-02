#include "populate.h"

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int count, int print_alert){

    char msg [255];
    char any[IP_ADDR_LEN_STR] = "any";
	for (int i = 0; i<count; i++){
	
        if(strstr(rules_ds[i].options,"msg") != NULL){

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
                        
            if(rules_ds[i].protocol == 1 || rules_ds[i].protocol == 3 || rules_ds[i].protocol == 4 || rules_ds[i].protocol == 6){

                if (!strcmp(rules_ds[i].ip_src, frame->data.source_ip) || !strcmp(rules_ds[i].ip_src,any)){      
                        
                    if (rules_ds[i].port_src == frame->data.data.source_port || rules_ds[i].port_src == 0){   

                        if (!strcmp(rules_ds[i].ip_dst, frame->data.destination_ip) || !strcmp(rules_ds[i].ip_dst,any)){       

                            if (rules_ds[i].port_dst == frame-> data.data.destination_port || rules_ds[i].port_dst == 0){    
                                
                                // ALERT
                                if (rules_ds[i].action == 1){

                                    if(rules_ds[i].protocol != 4){

                                        if(strstr(rules_ds[i].options,"content") != NULL){
                                            
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
                                    
                                    else {

                                        if(print_alert){
                                            printf("ALERT : %s\n", msg);
                                        }
                                        openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                        syslog(LOG_INFO, msg);
                                        closelog();
                                    }

                                }

                                // SAVE
                                else if(rules_ds[i].action == 2){
                                    
                                    char file[MAXLINE];

                                    if(strstr(rules_ds[i].options,"file") == NULL){
                                        strcpy(file,"save_msids");
                                    }
                                    else{
                                        char save_options [255];
                                        strcpy(save_options, rules_ds[i].options);
                                                
                                        char * pfile = strstr(save_options,"file");
                                        strtok(pfile,"\"");

                                        strcpy(file,strtok(NULL,"\""));
                                    }
                                    

                                    FILE *fic = fopen(file,"a");

                                    fputs("-----New frame-----\n",fic);
                                    char protocol[10];
                                    switch (rules_ds[i].protocol){
                                    case 1:
                                        strcpy(protocol,"TCP");
                                        break;
                                    
                                    case 3:
                                        strcpy(protocol,"HTTP");
                                        break;
                                    
                                    case 4:
                                        strcpy(protocol,"HTTPS");
                                        break;
                                        
                                    case 6:
                                        strcpy(protocol,"FTP");
                                        break;
                                    }
                                    fprintf(fic, "Protocol : %s\n", protocol);
                                    fprintf(fic, "IP : %s --> %s\n", frame->data.source_ip, frame->data.destination_ip);
                                    fprintf(fic, "Port : %d --> %d\n", frame->data.data.source_port, frame->data.data.destination_port);

                                    ///TIME
                                    time_t Time;
                                    struct tm *time_struct;
                                    char str_time[20];

                                    time(&Time);
                                    time_struct = localtime(&Time);
                                    bzero(str_time,20);
                                    strftime(str_time,20,"%d-%m-%Y at %H:%M:%S", time_struct);
                                    /// Source : https://www.developpez.net/forums/d558432/general-developpement/programmation-systeme/linux/heure-systeme-c/

                                    fprintf(fic, "%s\n", str_time);

                                    if(frame->data.data.data != NULL){
                                        fputs("~~~~~DATA~~~~~\n", fic);
                                        fputs((char*)frame->data.data.data, fic);
                                        fputs("\n\n\n",fic);
                                    }

                                    fclose(fic);

                                    
                                }
                            }		
                        }
                    }
                }
            }

            //IF UDP
            else if(rules_ds[i].protocol == 2){

                if (!strcmp(rules_ds[i].ip_src, frame->data.source_ip) || !strcmp(rules_ds[i].ip_src,any)){      
                        
                    if (rules_ds[i].port_src == frame->data.udp_data.source_port || rules_ds[i].port_src == 0){       

                        if (!strcmp(rules_ds[i].ip_dst, frame->data.destination_ip) || !strcmp(rules_ds[i].ip_dst,any)){      

                            if (rules_ds[i].port_dst == frame->data.udp_data.destination_port || rules_ds[i].port_dst == 0){       
                                
                                if (rules_ds[i].action == 1){

                                    if(strstr(rules_ds[i].options,"content") != NULL){
                                        char save_options [255];
                                        strcpy(save_options, rules_ds[i].options);

                                        char * pcontent = strstr(save_options,"content");
                                        strtok(pcontent,"\"");

                                        char * content = strtok(NULL,"\"");

                                        if((char *)frame->data.udp_data.data != NULL){ // check data != NULL

                                            if(strstr((char *)frame->data.udp_data.data,content) != NULL){
                                                if(print_alert){
                                                    printf("ALERT : %s\n", msg);
                                                }
                                                openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                                syslog(LOG_INFO, msg);
                                                closelog();
                                            }
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

                                // SAVE
                                else if(rules_ds[i].action == 2){
                                    
                                    char file[MAXLINE];
                                    
                                    if(strstr(rules_ds[i].options,"file") == NULL){
                                        strcpy(file,"save_msids");
                                    }
                                    else{
                                        char save_options [255];
                                        strcpy(save_options, rules_ds[i].options);
                                                
                                        char * pfile = strstr(save_options,"file");
                                        strtok(pfile,"\"");

                                        strcpy(file,strtok(NULL,"\""));
                                        printf("%s\n",file);
                                    }
                                    

                                    FILE *fic = fopen(file,"a");

                                    fputs("-----New frame-----\n",fic);
                                    fputs("Protocol : UDP\n",fic);
                                    fprintf(fic, "IP : %s --> %s\n", frame->data.source_ip, frame->data.destination_ip);
                                    fprintf(fic, "Port : %d --> %d\n", frame->data.udp_data.source_port, frame->data.udp_data.destination_port);

                                    ///TIME
                                    time_t Time;
                                    struct tm *time_struct;
                                    char str_time[20];

                                    time(&Time);
                                    time_struct = localtime(&Time);
                                    bzero(str_time,20);
                                    strftime(str_time,20,"%d-%m-%Y at %H:%M:%S", time_struct);
                                    /// Source : https://www.developpez.net/forums/d558432/general-developpement/programmation-systeme/linux/heure-systeme-c/

                                    fprintf(fic, "%s\n", str_time);

                                    if(frame->data.udp_data.data != NULL){
                                        fputs("~~~~~DATA~~~~~\n", fic);
                                        fputs((char*)frame->data.udp_data.data, fic);
                                        fputs("\n\n\n",fic);
                                    }

                                    fclose(fic);		
                                }
                            }
                        }
                    }
                }
            }

            // ARP
            else if (rules_ds[i].protocol == 5){
                
                if(rules_ds[i].action == 1){
                    if(print_alert){
                        printf("ALERT : %s\n", msg);
                    }
                    openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                    syslog(LOG_INFO, msg);
                    closelog();
                }

                else if(rules_ds[i].action == 2){
                                    
                    char file[MAXLINE];
                                    
                    if(strstr(rules_ds[i].options,"file") == NULL){
                        strcpy(file,"save_msids");
                    }
                    else{
                        char save_options [255];
                        strcpy(save_options, rules_ds[i].options);
                                                
                        char * pfile = strstr(save_options,"file");
                        strtok(pfile,"\"");

                        strcpy(file,strtok(NULL,"\""));
                        printf("%s\n",file);
                    }
                                    

                    FILE *fic = fopen(file,"a");

                    fputs("-----New frame-----\n",fic);
                    fputs("Protocol : ARP\n",fic);

                    ///TIME
                    time_t Time;
                    struct tm *time_struct;
                    char str_time[20];

                    time(&Time);
                    time_struct = localtime(&Time);
                    bzero(str_time,20);
                    strftime(str_time,20,"%d-%m-%Y at %H:%M:%S", time_struct);
                    // Source : https://www.developpez.net/forums/d558432/general-developpement/programmation-systeme/linux/heure-systeme-c/

                    fprintf(fic, "%s\n\n\n", str_time);

                    fclose(fic);	
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

                //ACTION alert = 1, save = 2
                action = strtok(rule," ");
                if(!strcmp(action,"alert")){
                    rules_ds[i].action = 1;
                }
                else if(!strcmp(action,"save")){
                    rules_ds[i].action = 2;
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
                else if(!strcmp(protocol,"ftp")){
                        rules_ds[i].protocol = 6;
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
