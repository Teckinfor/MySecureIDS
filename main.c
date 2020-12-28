  
#include "populate.h"
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define MAXLINE 255

struct ids_rule{
        int action;
        int protocol;
        char ip_src[IP_ADDR_LEN_STR];
        int port_src;
        char ip_dst[IP_ADDR_LEN_STR];
        int port_dst;
        char options[MAXLINE];
} typedef Rule;

struct args_loop{
        u_char args[2];
        Rule lst_rules[255];
        int n_rules;
}typedef Arguments;

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int count){

        char any[IP_ADDR_LEN_STR] = "any";
	for (int i = 0; i<count; i++){
	
                char *log_msg = rules_ds[i].options;

                if (rules_ds[i].protocol == show_protocol(frame)){
                        
                        if(rules_ds[i].protocol == 1 || rules_ds[i].protocol == 3){

                                if (rules_ds[i].ip_src == frame->data.source_ip || !strcmp(rules_ds[i].ip_src,any))
                                {      
                        
                                        if (rules_ds[i].port_src == frame->data.data.source_port || rules_ds[i].port_src == 0)
                                        {       

                                                if (rules_ds[i].ip_dst == frame->data.destination_ip || !strcmp(rules_ds[i].ip_dst,any))
                                                {       

                                                        if (rules_ds[i].port_dst == frame-> data.data.destination_port || rules_ds[i].port_dst == 0)
                                                        {       
                                                                if (rules_ds->action == 1)
                                                                {

                                                                printf("Packet : ALERT\n");
                                                                openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                                                syslog(LOG_INFO, log_msg);
                                                                closelog();

                                                                }			

                                                        }
                                                }
                                        }
                                }
                        }

                        else if(rules_ds[i].protocol == 2){

                                if (rules_ds[i].ip_src == frame->data.source_ip || !strcmp(rules_ds[i].ip_src,any))
                                {      
                        
                                        if (rules_ds[i].port_src == frame->data.udp_data.source_port || rules_ds[i].port_src == 0)
                                        {       

                                                if (rules_ds[i].ip_dst == frame->data.destination_ip || !strcmp(rules_ds[i].ip_dst,any))
                                                {       

                                                        if (rules_ds[i].port_dst == frame->data.udp_data.destination_port || rules_ds[i].port_dst == 0)
                                                        {       
                                                                if (rules_ds->action == 1)
                                                                {

                                                                printf("Packet : ALERT\n");
                                                                openlog("ALERT", LOG_PID|LOG_CONS,LOG_USER);
                                                                syslog(LOG_INFO, log_msg);
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


void read_rules(FILE * file, Rule *rules_ds, int count){
        char rule[MAXLINE];
        char *protocol;
        char* action;

        for(int i = 0; i < count; i++){
                fgets(rule,MAXLINE,file);

                action = strtok(rule," ");
                if(!strcmp(action,"alert")){
                        rules_ds[i].action = 1;
                }

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
                else {
                        rules_ds[i].protocol = 0;
                }

                char* ip_src = strtok(NULL," ");
                strcpy(rules_ds[i].ip_src,ip_src);

                char* port_src_buf = strtok(NULL," ");
                if(!strcmp(port_src_buf,"any")){
                        rules_ds[i].port_src = 0;
                }
                else {
                        char* endptr1;
                        rules_ds[i].port_src = (int)strtol(port_src_buf, &endptr1, 10);
                }

                strtok(NULL," "); //No direction

                char* ip_dst = strtok(NULL," ");
                strcpy(rules_ds[i].ip_dst,ip_dst);

                char* port_dst_buf = strtok(NULL," ");
                if(!strcmp(port_dst_buf, "any")){
                        rules_ds[i].port_dst = 0;
                }
                else {
                        char* endptr;
                        rules_ds[i].port_dst = (int)strtol(port_dst_buf, &endptr, 10);
                }

                char* opt = strtok(NULL,")");
                strcpy(rules_ds[i].options,opt);

                //Remove the first character from the options which is "("
                for(int j = 0; j < strlen(rules_ds[i].options); j++){
                        rules_ds[i].options[j] = rules_ds[i].options[j+1];
                }

        }

        
}


void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){

        Arguments * args_lst = (Arguments *) args;
        ETHER_Frame frame;
        populate_packet_ds(header,packet,&frame,args_lst->args);

        if(args_lst->args[1]){
                if(frame.ethernet_type == IPV4){
                        switch (show_protocol(&frame))
                        {
                        case 1:
                                printf("Protocol : TCP\n");
                                break;
                        case 2:
                                printf("Protocol : UDP\n");
                                break;
                        case 3:
                                printf("Protocol : HTTP\n");
                                break;
                        case 0:
                                printf("Protocol : Not referenced\n");
                                break;
                        
                        default:
                                break;
                        }

                        if(show_protocol(&frame) == 3){
                                printf("\n~~~~~DATA~~~~~\n");
                                print_payload(frame.data.data.data_length,frame.data.data.data);
                        }
                }
                
        }

        else if(args_lst->args[2]){
                if(show_protocol(&frame) == 3){
                                print_payload(frame.data.data.data_length,frame.data.data.data);
                        }
        }

        rule_matcher(args_lst->lst_rules,&frame,args_lst->n_rules);

}

void print_help_menu(){
    printf("MySecureIDS - msids\n");
    printf("Use : msids [interface] [options]\n");
    printf("\nOptions :\n");
    printf("-a         Set the rules file.\n           By default, this is the file named ids.rules which is located in the same folder as msids.\n\n");
    printf("-d         Show informations about all frames.\n           Normally, nothing is displayed when reading frames.\n\n");
    printf("-D         Show informations about HTTP frames.\n           Normally, nothing is displayed when reading frames.\n\n");
    printf("-l         Define the number of frames to read.\n           By default, the number of frames is fixed at 25.\n\n");
    printf("-p         Enable the print of alerts.\n           By default, alerts are just written in the syslog.\n\n");
    printf("\nFor more information, visit our GitHub :\nhttps://github.com/Teckinfor/MySecureIDS\n");
}

int main(int argc, char *argv[]) 
{

        int is_interface = 0;
        const char* device;
        int nloop;
        int is_nloop = 0;
        int is_help = 0;
        int is_address = 0;
        char* file_address;
        u_char display_all_frames = (u_char)0;
        u_char display_http = (u_char)0;

        for(int i = 0; i < argc; i++){
                
                //Setting up the interface
                if(argv[1]!=NULL){
                        
                    device = argv[1];
                    is_interface = 1;
                }

                //Setting up the number of loops
                if(!strcmp(argv[i], "-l")){
                        if(argv[i + 1] == NULL){
                                break;
                        }
                        else if(sscanf(argv[i + 1], "%d", &nloop) != 1){ //Check that the argument is an integer
                                printf("\"%s\" is a bad argument for loop -l\n",argv[i + 1]);
                                break;
                        }
                        char* endptr;
                        nloop = (int)strtol(argv[i+1], &endptr, 10); //To convert a pointer of char in an integer
                        is_nloop = 1;
                }

                //Display the help menu
                else if(!strcmp(argv[i],"-h")||!strcmp(argv[i],"--help")){
                        print_help_menu();
                        is_help = 1;
                }

                //Show all frames
                else if(!strcmp(argv[i],"-d")){
                        display_all_frames = (u_char)1;
                }

                //Show all frames
                else if(!strcmp(argv[i],"-D")){
                        display_http = (u_char)1;
                }

                //Set the rules file
                else if(!strcmp(argv[i],"-a")){
                    if(argv[i+1] == NULL){
                        printf("Rules file argument missing\n");
                        exit(1);
                    }
                    file_address = argv[i+1];
                    is_address = 1;
                    
                }
        }

        if(is_interface && !is_help){

                printf("MySecureIDS is running : \n");

                //Checking if an address was entered
                if(!is_address){
                    file_address = "ids.rules";
                }
                
                //Check the number of rules
                FILE *file = fopen(file_address,"r");
                int n_rules = 0;
                char rule[MAXLINE];

                if(file == NULL){
                        printf("An error occurred while reading the rules file\n");
                        exit(1);
                }
                while(fgets(rule,MAXLINE,file)!= NULL){
                        n_rules ++;
                }
                printf("%d rules have been found in %s\n",n_rules,file_address);
                fclose(file);

                //Read all rules
                FILE *rule_file = fopen(file_address,"r");
                Rule lst_rules[n_rules];
                read_rules(rule_file, lst_rules, n_rules);
                fclose(rule_file);
                
                //Listening on the interface
                printf("Listening on %s...\n", device);
                char error_buffer[PCAP_ERRBUF_SIZE];
                pcap_t *handle;

                handle = pcap_create(device,error_buffer);
                pcap_set_timeout(handle,10);
                pcap_activate(handle);

                if(!is_nloop){
                        nloop = 25;
                }

                //Check if display_all_frames and display_http are enabled
                if(display_all_frames && display_http){
                        printf("You can't use option -D and -d at the same time\n");
                        exit(1);
                }
                u_char arg_loop[2];
                if(display_all_frames){
                        arg_loop[1] = display_all_frames;
                }
                else if(display_http == 2){
                        arg_loop[2] = display_http;
                }

                Arguments argument_loop;
                argument_loop.args[0] = arg_loop[0];
                argument_loop.args[1] = arg_loop[1];
                for(int i = 0; i < n_rules; i++){
                        argument_loop.lst_rules[i].action = lst_rules[i].action;
                        argument_loop.lst_rules[i].protocol = lst_rules[i].protocol;
                        argument_loop.lst_rules[i].port_dst = lst_rules[i].port_dst;
                        argument_loop.lst_rules[i].port_src = lst_rules[i].port_src;

                        strcpy(argument_loop.lst_rules[i].ip_dst, lst_rules[i].ip_dst);
                        strcpy(argument_loop.lst_rules[i].ip_src, lst_rules[i].ip_src);
                        strcpy(argument_loop.lst_rules[i].options, lst_rules[i].options);
                }
                argument_loop.n_rules = n_rules;

                pcap_loop(handle, nloop, my_packet_handler, (u_char*)&argument_loop);

                return 0;
        }
        else if(!is_help){
                printf("Missing arguments. Do \"ids --help\" or \"ids -h\" for more information.\n");
        }
        
}
