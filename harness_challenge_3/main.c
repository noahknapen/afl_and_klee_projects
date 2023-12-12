#include "stdio.h"
#include "stdlib.h"
#include "dns.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "string.h"
#include "emsettings.h"
#include "emdns.h"
#include "masterfile.h"
#include "unistd.h"

#define PORT     5959
#define BUF_SIZE  128 

int main(int argc, char** argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    
    char buf_response[BUF_SIZE]; 
    char input[BUF_SIZE];
    
    uint16_t answer_len;
    fgets(input, BUF_SIZE, stdin);
    emdns_resolve_raw(input, buf_response, BUF_SIZE, &answer_len); // FUZZ TARGET BY REPLACING buf_request WITH stdin

    return (EXIT_SUCCESS);
}

