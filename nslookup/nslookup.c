/*
C code for nslookup binary

Features:
input URL and it returns IP address, showing all servers

TODO:
Reverse lookup
Add flags for help and reverse lookup
*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main (int argc, char *argv[]){
    struct addrinfo hints, *res, *p;
    int status;

    if (argc != 2){
        fprintf(stderr, "No domain listed");
        return 1;
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    if ((status = getaddrinfo(argv[1], NULL, &hints, &res) != 0)){
        fprintf(stderr, "Error in getarrdinfo(): %s\n", gai_strerror(status));
        return 2;
    }

    printf("Get addrinfo for %s\n", argv[1]);

    // Go though all the linked lists until we find a valid one
    char ipstr[INET6_ADDRSTRLEN];

    for (p = res; p != NULL; p = p->ai_next){
        void *addr;
        char *ipver;


        if (p->ai_family == AF_INET){
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        printf("Details of getaddr: \n");

        if (p->ai_canonname) {
            printf("    Canonical name: %s\n", p->ai_canonname);
        }
        // printf("    ai_socketype: %d\n", p->ai_socktype); // tells you IPv4 or v6
        // printf("    ai_protocol: %d\n", p->ai_protocol); //idk what this means

        // printf("    sa_data: %s\n", addr); // this prints a bunch of garbage, needs translated

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("    %s: %s\n", ipver, ipstr);

    }

    // This is the basics, most of the progams will have all this


    freeaddrinfo(res);
    return 0;
}
