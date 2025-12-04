/*
C code for ping binary - Cross-platform compatible (macOS/Linux)
Based off https://www.geeksforgeeks.org/computer-networks/ping-in-c/

TODO:
understand ping better, understand ICMP
Different packet size
Takes IPv4, IPv6, and URL as input

Default is endless pings, make an option to manually send x pings
    Ping 8.8.8.8 -c 6
Stats at end of ping, packet loss, packet transmitted, time, rtt, etc
Alternatives to ICMP? bypass firewall?
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

// Platform-specific includes and definitions
#ifdef __APPLE__
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    // macOS/BSD systems use 'icmp' structure
    #define icmphdr icmp
    #define ICMP_ECHO_REQUEST ICMP_ECHO
    // Field mappings for macOS
    #define icmp_id icmp_hun.ih_idseq.icd_id
    #define icmp_seq icmp_hun.ih_idseq.icd_seq
#else
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    // Linux uses different structure
    #define ICMP_ECHO_REQUEST ICMP_ECHO
#endif

#define PACKETSIZE  64
#define PORTNUM 0
#define SLEEPRATE 100000 // ping sleep rate (microseconds)
#define RECV_TIMEOUT 2  // timeout for receiving packets (seconds)

int pingloop = 1;

// Ping packet structure
struct ping_pckt {
    struct icmphdr hdr;
    char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

// Function declarations
unsigned short checksum(void *b, int len);
void intHandler(int dummy);
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con);
char *reverse_dns_lookup(char *ip_addr);
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_dom, char *ping_ip, char *rev_host);

// RFC 1071 checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    // Add all 16-bit words
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    // Left over byte, pad with zero
    if (len == 1) {
        sum += *(unsigned char*)buf << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    result = ~sum;
    return result;
}

void intHandler(int dummy) {
    pingloop = 0;
}

// DNS lookup function
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) {
    printf("Resolving DNS...\n");
    struct hostent *host_entity;
    char *ip = (char *)malloc(NI_MAXHOST * sizeof(char));
    
    if (!ip) {
        printf("Memory allocation failed!\n");
        return NULL;
    }

    if ((host_entity = gethostbyname(addr_host)) == NULL) {
        free(ip);
        return NULL;
    }

    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr));
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons(PORTNUM);
    (*addr_con).sin_addr.s_addr = *(long *)host_entity->h_addr;

    return ip;
}

// Reverse DNS lookup
char *reverse_dns_lookup(char *ip_addr) {
    struct sockaddr_in temp_addr;
    socklen_t len;
    char buf[NI_MAXHOST], *ret_buf;

    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *)&temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD)) {
        printf("Could not resolve reverse lookup of hostname\n");
        return NULL;
    }

    ret_buf = (char *)malloc((strlen(buf) + 1) * sizeof(char));
    if (!ret_buf) {
        printf("Memory allocation failed!\n");
        return NULL;
    }
    
    strcpy(ret_buf, buf);
    return ret_buf;
}

// Cross-platform ICMP field setters, this was annoying
void set_icmp_id_seq(struct icmphdr *hdr, int id, int seq) {
#ifdef __APPLE__
    hdr->icmp_id = id;
    hdr->icmp_seq = seq;
#else
    hdr->un.echo.id = id;
    hdr->un.echo.sequence = seq;
#endif
}

// Cross-platform ICMP field getters
int get_icmp_id(struct icmphdr *hdr) {
#ifdef __APPLE__
    return hdr->icmp_id;
#else
    return hdr->un.echo.id;
#endif
}

int get_icmp_seq(struct icmphdr *hdr) {
#ifdef __APPLE__
    return hdr->icmp_seq;
#else
    return hdr->un.echo.sequence;
#endif
}

// Main ping function
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_dom, char *ping_ip, char *rev_host) {
    int ttl = 64, msg_count = 0, i, addr_len, msg_rec = 0, flag = 1;
    char rbuf[512]; //Play with this piece
    struct ping_pckt pckt;
    struct sockaddr_in r_addr;
    struct timespec startTime, endTime, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    int sock_buf_size = 65536;
    
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);

    // Set socket options
    if (setsockopt(ping_sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        printf("Setting socket options failed for TTL!\n");
        return;
    }
    
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));

    printf("\nPING %s (%s): %d data bytes\n", ping_dom ? ping_dom : ping_ip, ping_ip, PACKETSIZE);

    while (pingloop) {
        flag = 1;

        // Prepare packet
        bzero(&pckt, sizeof(pckt));
        pckt.hdr.icmp_type = ICMP_ECHO_REQUEST;
        pckt.hdr.icmp_code = 0;
        
        // Set ID and sequence number (cross-platform)
        set_icmp_id_seq(&pckt.hdr, getpid(), msg_count);

        // Fill message payload
        for (i = 0; i < sizeof(pckt.msg) - 1; i++)
            pckt.msg[i] = i + '0';
        pckt.msg[i] = 0;

        // Calculate checksum (zero it first)
        pckt.hdr.icmp_cksum = 0;
        pckt.hdr.icmp_cksum = checksum(&pckt, sizeof(pckt));

        msg_count++;

        // Send packet
        clock_gettime(CLOCK_MONOTONIC, &startTime);
        if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)ping_addr, sizeof(*ping_addr)) <= 0) {
            printf("Packet sending failed! Error: %s\n", strerror(errno));
            flag = 0;
        }

        // Receive packet
        addr_len = sizeof(r_addr);
        int recv_bytes = recvfrom(ping_sockfd, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&r_addr, &addr_len);
        
        if (recv_bytes <= 0) {
            if (msg_count > 1) {  // Don't show error for first packet
                printf("Request timeout for icmp_seq %d\n", msg_count - 1);
            }
        } else {
            clock_gettime(CLOCK_MONOTONIC, &endTime);

            if (flag) {  // Only process if packet was sent successfully
                struct ip *ip_hdr = (struct ip*)rbuf;
                int ip_hdr_len = ip_hdr->ip_hl << 2;
                struct icmphdr *recv_hdr = (struct icmphdr *)(rbuf + ip_hdr_len);

                // Get ID and sequence from received packet
                int recv_id = get_icmp_id(recv_hdr);
                int recv_seq = get_icmp_seq(recv_hdr);

                if (recv_hdr->icmp_type == 0 && recv_hdr->icmp_code == 0) {
                    // Check if this is our packet
                    if (recv_id == getpid() && recv_seq == (msg_count - 1)) {
                        // Calculate RTT
                        double timeElapsed = (endTime.tv_nsec - startTime.tv_nsec) / 1000000.0;
                        rtt_msec = (endTime.tv_sec - startTime.tv_sec) * 1000.0 + timeElapsed;

                        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3Lf ms\n", 
                               PACKETSIZE, ping_ip, recv_seq, ttl, rtt_msec);
                        msg_rec++;
                    } else {
                        // Packet from different ping process, ignore
                    }
                } else {
                    printf("Error: Packet received with ICMP type %d code %d\n", 
                           recv_hdr->icmp_type, recv_hdr->icmp_code);
                }
            }
        }

        // Sleep before next ping
        usleep(SLEEPRATE);
    }

    // Calculate total time and print statistics
    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;

    printf("\n--- %s ping statistics ---\n", ping_ip);
    if (msg_count > 0) {
        double loss_percent = ((double)(msg_count - msg_rec) / msg_count) * 100.0;
        printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n", 
               msg_count, msg_rec, loss_percent);
        printf("round-trip min/avg/max = %.3Lf ms\n", total_msec / msg_count);
    } else {
        printf("0 packets transmitted\n");
    }
}

// Main function
int main(int argc, char *argv[]) {
    int sockfd;
    char *ip_addr, *reverse_hostname;
    struct sockaddr_in addr_con;

    if (argc != 2) {
        printf("Usage: %s <hostname or IP address>\n", argv[0]);
        printf("Example: %s google.com\n", argv[0]);
        printf("Example: %s 8.8.8.8\n", argv[0]);
        return 1;
    }

    // DNS lookup
    ip_addr = dns_lookup(argv[1], &addr_con);
    if (ip_addr == NULL) {
        printf("DNS lookup failed! Could not resolve hostname: %s\n", argv[1]);
        return 1;
    }

    // Reverse DNS lookup
    reverse_hostname = reverse_dns_lookup(ip_addr);
    
    printf("Trying to connect to '%s' IP: %s\n", argv[1], ip_addr);
    if (reverse_hostname) {
        printf("Reverse lookup domain: %s\n", reverse_hostname);
    }

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        printf("Socket creation failed! Error: %s\n", strerror(errno));
        printf("Note: This program requires root privileges (try with sudo)\n");
        free(ip_addr);
        if (reverse_hostname) free(reverse_hostname);
        return 1;
    }

    // Set up signal handler for graceful shutdown
    signal(SIGINT, intHandler);

    // Start pinging
    send_ping(sockfd, &addr_con, reverse_hostname, ip_addr, argv[1]);

    // Cleanup
    close(sockfd);
    free(ip_addr);
    if (reverse_hostname) free(reverse_hostname);
    
    return 0;
}