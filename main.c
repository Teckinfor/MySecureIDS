#include "populate.h"
#include "help.c"

//GLOBAL
int count_frame = 1;
int display_all_frames = 0;
int display_http = 0;
int print_alert = 0;
//////////////////////

void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){

        Arguments * args_lst = (Arguments *) args;
        ETHER_Frame frame;
        populate_packet_ds(header,packet,&frame,display_all_frames,count_frame);

        if(display_all_frames){
                if (frame.ethernet_type == ARP){
                        printf("Protocol : ARP\n");
                }
                else if(frame.ethernet_type == IPV4){
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
                        case 4:
                                printf("Protocol : HTTPS\n");
                                break;
                        case 6:
                                printf("Protocol : FTP\n");
                                break;
                        case 0:
                                printf("Protocol : Not referenced\n");
                                break;
                        
                        default:
                                break;
                        }

                        if(show_protocol(&frame) == 3 || show_protocol(&frame) == 6){
                                printf("\n~~~~~DATA~~~~~\n");
                                print_payload(frame.data.data.data_length,frame.data.data.data);
                        }
                }
                
        }

        else if(display_http){

                if(show_protocol(&frame) == 3){

                        print_payload(frame.data.data.data_length,frame.data.data.data);
                }
        }

        rule_matcher(args_lst->lst_rules, &frame, args_lst->n_rules, print_alert);

        count_frame++;

        //Clean buffer
        frame.ethernet_type = 0;
        frame.data.protocol_ip = 0;

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
                        display_all_frames = 1;
                }

                //Show all frames
                else if(!strcmp(argv[i],"-D")){
                        display_http = 1;
                }

                //Show alerts
                else if(!strcmp(argv[i],"-p")){
                        print_alert = 1;
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
                        nloop = 1000;
                }

                //Check if display_all_frames and display_http are enabled
                if(display_all_frames && display_http){
                        printf("You can't use option -D and -d at the same time\n");
                        exit(1);
                }

                Arguments argument_loop;
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
                printf("Missing arguments. Do \"msids --help\" or \"msids -h\" for more information.\n");
        }
        
}
