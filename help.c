#include <stdio.h>

void print_help_menu(){
    printf("MySecureIDS - msids\n");
    printf("Use : msids [interface] <options>\n");
    printf("\nOptions :\n");
    printf("-a         Set the rules file.\n           By default, this is the file named ids.rules which is located in the same folder as msids.\n\n");
    printf("-d         Show informations about all frames.\n           Normally, nothing is displayed when reading frames.\n\n");
    printf("-D         Show informations about HTTP frames.\n           Normally, nothing is displayed when reading frames.\n\n");
    printf("-l         Define the number of frames to read.\n           By default, the number of frames is fixed at 1000.\n\n");
    printf("-p         Enable the print of alerts.\n           By default, alerts are just written in the syslog.\n\n");
    printf("\nFor more information, visit our GitHub :\nhttps://github.com/Teckinfor/MySecureIDS\n");
}
