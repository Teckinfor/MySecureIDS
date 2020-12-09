  
#include "populate.h"
#include <stdlib.h>
#include <string.h>

#define MAXLINE 255

struct ids_rule{
        char* action;
        char* protocol;
        char* ip_src;
        char* port_src;
        char* direction;
        char* ip_dst;
        char* port_dst;
        char* options;
} typedef Rule;

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame){
}


void read_rules(FILE * file, Rule *rules_ds, int count){
        char rule[MAXLINE];
        for(int i = 0; i < count; i++){
                fgets(rule,MAXLINE,file);
                rules_ds[i].action = strtok(rule," ");
                rules_ds[i].protocol = strtok(NULL," ");
                rules_ds[i].ip_src = strtok(NULL," ");
                rules_ds[i].port_src = strtok(NULL," ");
                rules_ds[i].direction = strtok(NULL," ");
                rules_ds[i].ip_dst = strtok(NULL," ");
                rules_ds[i].port_dst = strtok(NULL," ");
                rules_ds[i].options = strtok(NULL,")");

                //Remove the first character from the options which is "("
                for(int j = 0; j < strlen(rules_ds[i].options); j++){
                        rules_ds[i].options[j] = rules_ds[i].options[j+1];
                }
        }
}


void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){

}

void print_help_menu(){
    printf("MySecureIDS - msids\n");
    printf("Use : msids [interface] [options]\n");
    printf("\nOptions :\n");
    printf("-a         Set the rules file.\n           By default, this is the file named ids.rules which is located in the same folder as msids.\n\n");
    printf("-l         Define the number of frames to read.\n           By default, the number of frames is fixed at 25.\n\n");
    printf("\nFor more information, visit our GitHub :\nhttps://github.com/Teckinfor/MySecureIDS\n");
}

int main(int argc, char *argv[]) 
{

        //char *device = argv[1];
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

                pcap_loop(handle, nloop, my_packet_handler, NULL);

                return 0;
        }
        else if(!is_help){
                printf("Missing arguments. Do \"ids --help\" or \"ids -h\" for more information.\n");
        }
        
}
