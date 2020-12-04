#include "populate.h"

struct ids_rule
{
} typedef Rule;

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
}


void read_rules(FILE * file, Rule *rules_ds, int count)
{

}


void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)

{

}

void print_help_menu(){
    printf("MySecureIDS - msids\n");
    printf("Use : msids [interface] [options]\n");
    printf("\nOptions :\n");
    printf("-l,      define the number of frames to read\n");
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
        for(int i = 0; i < argc; i++){
                
                //Setting up the interface
                if(!strcmp(argv[i], "-d")){
                        
                        device = argv[i + 1];
                        is_interface = 1;
                }

                //Setting up the number of loops
                else if(!strcmp(argv[i], "-l")){
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
        }

        if(is_interface && is_nloop && !is_help){
                printf("Listening on %s...\n", device);
                char error_buffer[PCAP_ERRBUF_SIZE];
                pcap_t *handle;

                handle = pcap_create(device,error_buffer);
                pcap_set_timeout(handle,10);
                pcap_activate(handle);

                pcap_loop(handle, nloop, my_packet_handler, NULL);

                return 0;
        }
        else if(!is_help){
                printf("Missing arguments. Do \"ids --help\" or \"ids -h\" for more information.\n");
        }
        
}
