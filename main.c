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

int main(int argc, char *argv[]) 
{

        char *device = "eth0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 10;

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;
}
