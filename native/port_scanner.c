/*
 * port_scanner.c
 * BlackHunter Pro - High-Performance Port Scanner
 * Multi-threaded TCP port scanner written in C
 * Academic Penetration Testing Tool - Isolated Lab Only
 *
 * Compile: gcc -O2 -pthread -o port_scanner port_scanner.c
 * Usage:   ./port_scanner <host> <timeout> <threads> [start_port] [end_port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>

/* ============================================= */
/* CONFIGURATION */
/* ============================================= */

#define MAX_THREADS 500
#define DEFAULT_TIMEOUT 2
#define DEFAULT_THREADS 100
#define MAX_OPEN_PORTS 65536
#define BANNER_SIZE 1024

/* ============================================= */
/* DATA STRUCTURES */
/* ============================================= */

typedef struct {
    char host[256];
    int port;
    int timeout;
} PortTask;

typedef struct {
    int port;
    char service[64];
    char banner[BANNER_SIZE];
    int state; /* 0 = closed, 1 = open, 2 = filtered */
} PortResult;

typedef struct {
    PortResult results[MAX_OPEN_PORTS];
    int count;
    pthread_mutex_t lock;
} ResultList;

typedef struct {
    PortTask *tasks;
    int task_count;
    int next_task;
    pthread_mutex_t lock;
    ResultList *results;
} TaskQueue;

/* ============================================= */
/* GLOBAL VARIABLES */
/* ============================================= */

static volatile int g_running = 1;
static ResultList g_results;
static TaskQueue g_queue;
static int g_timeout = DEFAULT_TIMEOUT;

/* ============================================= */
/* SERVICE DATABASE */
/* ============================================= */

typedef struct {
    int port;
    const char *service;
} ServiceEntry;

static const ServiceEntry SERVICES[] = {
    {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
    {53, "DNS"}, {69, "TFTP"}, {79, "Finger"}, {80, "HTTP"},
    {81, "HTTP-Alt"}, {88, "Kerberos"}, {110, "POP3"}, {111, "RPCbind"},
    {113, "Ident"}, {119, "NNTP"}, {123, "NTP"}, {135, "MSRPC"},
    {137, "NetBIOS-NS"}, {138, "NetBIOS-DGM"}, {139, "NetBIOS-SSN"},
    {143, "IMAP"}, {161, "SNMP"}, {162, "SNMPTrap"}, {179, "BGP"},
    {194, "IRC"}, {389, "LDAP"}, {443, "HTTPS"}, {445, "SMB"},
    {465, "SMTPS"}, {500, "ISAKMP"}, {514, "Syslog"}, {515, "LPD"},
    {520, "RIP"}, {548, "AFP"}, {554, "RTSP"}, {587, "SMTP-Submit"},
    {631, "IPP"}, {636, "LDAPS"}, {646, "LDP"}, {873, "Rsync"},
    {990, "FTP-SSL"}, {993, "IMAPS"}, {995, "POP3S"},
    {1025, "NFS"}, {1026, "NFS"}, {1027, "NFS"}, {1028, "NFS"},
    {1080, "SOCKS"}, {1194, "OpenVPN"}, {1433, "MSSQL"},
    {1434, "MSSQL-Browser"}, {1521, "Oracle"}, {1701, "L2TP"},
    {1720, "H.323"}, {1723, "PPTP"}, {1755, "MMS"}, {1812, "RADIUS"},
    {1900, "SSDP"}, {2000, "Cisco-SCCP"}, {2049, "NFS"},
    {2082, "cPanel"}, {2083, "cPanel-SSL"}, {2086, "WHM"},
    {2087, "WHM-SSL"}, {2222, "SSH-Alt"}, {2323, "Telnet-Alt"},
    {2375, "Docker"}, {2376, "Docker-SSL"}, {3000, "Node.js"},
    {3128, "Squid-Proxy"}, {3260, "iSCSI"}, {3306, "MySQL"},
    {3389, "RDP"}, {3690, "SVN"}, {4000, "HTTP-Alt"},
    {4333, "mSQL"}, {4443, "HTTPS-Alt"}, {4444, "Metasploit"},
    {4505, "SaltStack"}, {4506, "SaltStack"}, {5000, "UPnP"},
    {5001, "HTTP-Alt"}, {5005, "Java-RMI"}, {5432, "PostgreSQL"},
    {5433, "PostgreSQL-Alt"}, {5672, "AMQP"}, {5900, "VNC"},
    {5901, "VNC-Alt"}, {5984, "CouchDB"}, {5985, "WinRM-HTTP"},
    {5986, "WinRM-HTTPS"}, {6000, "X11"}, {6379, "Redis"},
    {6443, "Kubernetes-API"}, {6666, "IRC-Alt"}, {7000, "Cassandra"},
    {7070, "HTTP-Alt"}, {8000, "HTTP-Alt"}, {8001, "HTTP-Alt"},
    {8008, "HTTP-Alt"}, {8080, "HTTP-Proxy"}, {8081, "HTTP-Alt"},
    {8086, "InfluxDB"}, {8088, "HTTP-Alt"}, {8090, "HTTP-Alt"},
    {8443, "HTTPS-Alt"}, {8888, "HTTP-Alt"}, {9000, "HTTP-Alt"},
    {9090, "HTTP-Alt"}, {9200, "Elasticsearch"}, {9300, "Elasticsearch"},
    {9443, "HTTPS-Alt"}, {9999, "HTTP-Alt"}, {10000, "Webmin"},
    {11211, "Memcached"}, {15672, "RabbitMQ"}, {27017, "MongoDB"},
    {27018, "MongoDB-Alt"}, {50000, "SAP"}, {50070, "Hadoop"},
    {50075, "Hadoop"}, {50090, "Hadoop"},
    {0, NULL}
};

static const char* get_service_name(int port) {
    for (int i = 0; SERVICES[i].service != NULL; i++) {
        if (SERVICES[i].port == port) {
            return SERVICES[i].service;
        }
    }
    return "Unknown";
}

/* ============================================= */
/* RESOLVE HOST */
/* ============================================= */

static int resolve_host(const char *hostname, char *ip_out) {
    struct hostent *he;
    struct in_addr **addr_list;

    he = gethostbyname(hostname);
    if (he == NULL) {
        return -1;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        strcpy(ip_out, inet_ntoa(*addr_list[0]));
        return 0;
    }

    return -1;
}

/* ============================================= */
/* SET SOCKET TIMEOUT */
/* ============================================= */

static int set_socket_timeout(int sock, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }

    return 0;
}

/* ============================================= */
/* SCAN SINGLE PORT */
/* ============================================= */

static int scan_port(const char *host, int port, int timeout, char *banner_out) {
    int sock;
    struct sockaddr_in target;
    struct timeval tv;
    int result;

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    /* Set non-blocking for timeout control */
    fcntl(sock, F_SETFL, O_NONBLOCK);

    /* Set timeout */
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Setup target */
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, host, &target.sin_addr);

    /* Attempt connection */
    result = connect(sock, (struct sockaddr *)&target, sizeof(target));

    if (result < 0) {
        if (errno == EINPROGRESS) {
            /* Wait for connection */
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);

            tv.tv_sec = timeout;
            tv.tv_usec = 0;

            if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

                if (so_error == 0) {
                    /* Connection successful - try to grab banner */
                    if (banner_out != NULL) {
                        /* Set blocking for banner grab */
                        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);

                        /* Send probe for HTTP services */
                        if (port == 80 || port == 8080 || port == 8000 ||
                            port == 8008 || port == 8081 || port == 8888) {
                            const char *probe = "HEAD / HTTP/1.0\r\n\r\n";
                            send(sock, probe, strlen(probe), 0);
                        }

                        /* Receive banner */
                        int bytes = recv(sock, banner_out, BANNER_SIZE - 1, 0);
                        if (bytes > 0) {
                            banner_out[bytes] = '\0';
                            /* Clean up banner - remove newlines */
                            for (int i = 0; i < bytes; i++) {
                                if (banner_out[i] == '\r' || banner_out[i] == '\n') {
                                    banner_out[i] = ' ';
                                }
                            }
                        } else {
                            banner_out[0] = '\0';
                        }
                    }

                    close(sock);
                    return 1; /* Open */
                }
            }
        }

        close(sock);
        return 0; /* Closed/Filtered */
    }

    /* Immediate connection */
    if (banner_out != NULL) {
        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);

        if (port == 80 || port == 8080 || port == 8000 ||
            port == 8008 || port == 8081 || port == 8888) {
            const char *probe = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, probe, strlen(probe), 0);
        }

        int bytes = recv(sock, banner_out, BANNER_SIZE - 1, 0);
        if (bytes > 0) {
            banner_out[bytes] = '\0';
            for (int i = 0; i < bytes; i++) {
                if (banner_out[i] == '\r' || banner_out[i] == '\n') {
                    banner_out[i] = ' ';
                }
            }
        } else {
            banner_out[0] = '\0';
        }
    }

    close(sock);
    return 1; /* Open */
}

/* ============================================= */
/* ADD RESULT */
/* ============================================= */

static void add_result(int port, int state, const char *banner) {
    pthread_mutex_lock(&g_results.lock);

    if (g_results.count < MAX_OPEN_PORTS) {
        PortResult *r = &g_results.results[g_results.count];
        r->port = port;
        r->state = state;
        strncpy(r->service, get_service_name(port), sizeof(r->service) - 1);
        r->service[sizeof(r->service) - 1] = '\0';

        if (banner != NULL && banner[0] != '\0') {
            strncpy(r->banner, banner, sizeof(r->banner) - 1);
            r->banner[sizeof(r->banner) - 1] = '\0';
        } else {
            r->banner[0] = '\0';
        }

        g_results.count++;
    }

    pthread_mutex_unlock(&g_results.lock);
}

/* ============================================= */
/* GET NEXT PORT FROM QUEUE */
/* ============================================= */

static int get_next_port(void) {
    int port = -1;

    pthread_mutex_lock(&g_queue.lock);

    if (g_queue.next_task < g_queue.task_count) {
        port = g_queue.tasks[g_queue.next_task].port;
        g_queue.next_task++;
    }

    pthread_mutex_unlock(&g_queue.lock);

    return port;
}

/* ============================================= */
/* WORKER THREAD */
/* ============================================= */

static void* worker_thread(void *arg) {
    const char *host = (const char *)arg;
    char banner[BANNER_SIZE];

    while (g_running) {
        int port = get_next_port();

        if (port < 0) {
            break; /* No more ports */
        }

        banner[0] = '\0';

        int state = scan_port(host, port, g_timeout, banner);

        if (state == 1) {
            add_result(port, state, banner);
        }
    }

    return NULL;
}

/* ============================================= */
/* PRINT USAGE */
/* ============================================= */

static void print_usage(const char *prog) {
    printf("BlackHunter Pro - Port Scanner\n");
    printf("Usage: %s <host> [timeout] [threads] [start_port] [end_port]\n", prog);
    printf("\n");
    printf("Arguments:\n");
    printf("  host       - Target hostname or IP\n");
    printf("  timeout    - Connection timeout in seconds (default: %d)\n", DEFAULT_TIMEOUT);
    printf("  threads    - Number of threads (default: %d, max: %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  start_port - Start port (default: 1)\n");
    printf("  end_port   - End port (default: 65535)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.1\n", prog);
    printf("  %s 192.168.1.1 2 200\n", prog);
    printf("  %s 192.168.1.1 2 200 1 1000\n", prog);
    printf("  %s example.com 3 100 80 443\n", prog);
    printf("\n");
}

/* ============================================= */
/* PRINT BANNER */
/* ============================================= */

static void print_banner(void) {
    printf("\n");
    printf("\033[1;31m");
    printf("  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗\n");
    printf("  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║\n");
    printf("  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║\n");
    printf("  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║\n");
    printf("  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║\n");
    printf("  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n");
    printf("\033[0m");
    printf("\033[1;36m");
    printf("                   High-Performance Port Scanner\n");
    printf("                   Academic Penetration Testing Tool\n");
    printf("\033[0m");
    printf("\n");
}

/* ============================================= */
/* PRINT RESULTS */
/* ============================================= */

static void print_results(void) {
    if (g_results.count == 0) {
        printf("\033[1;33m[!] No open ports found\033[0m\n");
        return;
    }

    printf("\033[1;32m[+] Found %d open ports:\033[0m\n\n", g_results.count);

    /* Sort results by port */
    for (int i = 0; i < g_results.count - 1; i++) {
        for (int j = i + 1; j < g_results.count; j++) {
            if (g_results.results[i].port > g_results.results[j].port) {
                PortResult temp = g_results.results[i];
                g_results.results[i] = g_results.results[j];
                g_results.results[j] = temp;
            }
        }
    }

    /* Print header */
    printf("\033[1;36m");
    printf("┌──────────┬──────────────────────┬─────────────────────────────────────────┐\n");
    printf("│   PORT   │       SERVICE        │                 BANNER                  │\n");
    printf("├──────────┼──────────────────────┼─────────────────────────────────────────┤\n");
    printf("\033[0m");

    /* Print each port */
    for (int i = 0; i < g_results.count; i++) {
        PortResult *r = &g_results.results[i];

        /* Color based on risk */
        if (r->port == 21 || r->port == 23 || r->port == 445 || r->port == 3389) {
            printf("\033[1;31m"); /* Red - dangerous */
        } else if (r->port == 22 || r->port == 3306 || r->port == 5432 ||
                   r->port == 6379 || r->port == 27017) {
            printf("\033[1;33m"); /* Yellow - sensitive */
        } else {
            printf("\033[1;32m"); /* Green - normal */
        }

        printf("│ %-8d │ %-20s │ ", r->port, r->service);

        if (r->banner[0] != '\0') {
            char banner_short[40];
            strncpy(banner_short, r->banner, 37);
            banner_short[37] = '\0';
            if (strlen(r->banner) > 37) {
                strcat(banner_short, "...");
            }
            printf("%-39s", banner_short);
        } else {
            printf("%-39s", "-");
        }

        printf(" │\n");
        printf("\033[0m");
    }

    printf("\033[1;36m");
    printf("└──────────┴──────────────────────┴─────────────────────────────────────────┘\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* SIGNAL HANDLER */
/* ============================================= */

#include <signal.h>

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ============================================= */
/* MAIN */
/* ============================================= */

int main(int argc, char *argv[]) {
    char ip[64];
    const char *host;
    int threads = DEFAULT_THREADS;
    int start_port = 1;
    int end_port = 65535;
    int total_ports;

    /* Print banner */
    print_banner();

    /* Check arguments */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    host = argv[1];

    /* Parse timeout */
    if (argc >= 3) {
        g_timeout = atoi(argv[2]);
        if (g_timeout < 1) g_timeout = DEFAULT_TIMEOUT;
    }

    /* Parse threads */
    if (argc >= 4) {
        threads = atoi(argv[3]);
        if (threads < 1) threads = DEFAULT_THREADS;
        if (threads > MAX_THREADS) threads = MAX_THREADS;
    }

    /* Parse port range */
    if (argc >= 5) {
        start_port = atoi(argv[4]);
        if (start_port < 1) start_port = 1;
    }

    if (argc >= 6) {
        end_port = atoi(argv[5]);
        if (end_port > 65535) end_port = 65535;
    }

    if (start_port > end_port) {
        fprintf(stderr, "\033[1;31m[!] Invalid port range\033[0m\n");
        return 1;
    }

    /* Resolve host */
    printf("\033[1;36m[*] Resolving %s...\033[0m\n", host);

    if (resolve_host(host, ip) < 0) {
        fprintf(stderr, "\033[1;31m[!] Failed to resolve host: %s\033[0m\n", host);
        return 1;
    }

    printf("\033[1;32m[+] IP: %s\033[0m\n", ip);
    printf("\033[1;36m[*] Timeout: %d second(s)\033[0m\n", g_timeout);
    printf("\033[1;36m[*] Threads: %d\033[0m\n", threads);
    printf("\033[1;36m[*] Port range: %d-%d\033[0m\n", start_port, end_port);

    total_ports = end_port - start_port + 1;
    printf("\033[1;36m[*] Total ports: %d\033[0m\n", total_ports);
    printf("\033[1;36m[*] Scanning...\033[0m\n\n");

    /* Initialize results */
    memset(&g_results, 0, sizeof(g_results));
    pthread_mutex_init(&g_results.lock, NULL);

    /* Initialize queue */
    g_queue.tasks = (PortTask *)malloc(sizeof(PortTask) * total_ports);
    if (g_queue.tasks == NULL) {
        fprintf(stderr, "\033[1;31m[!] Memory allocation failed\033[0m\n");
        return 1;
    }

    for (int i = 0; i < total_ports; i++) {
        g_queue.tasks[i].port = start_port + i;
    }

    g_queue.task_count = total_ports;
    g_queue.next_task = 0;
    g_queue.results = &g_results;
    pthread_mutex_init(&g_queue.lock, NULL);

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Start timer */
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);

    /* Create threads */
    pthread_t *thread_ids = (pthread_t *)malloc(sizeof(pthread_t) * threads);
    if (thread_ids == NULL) {
        fprintf(stderr, "\033[1;31m[!] Thread allocation failed\033[0m\n");
        free(g_queue.tasks);
        return 1;
    }

    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_ids[i], NULL, worker_thread, (void *)ip) != 0) {
            fprintf(stderr, "\033[1;31m[!] Failed to create thread %d\033[0m\n", i);
            threads = i;
            break;
        }
    }

    /* Wait for all threads */
    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    /* Calculate elapsed time */
    gettimeofday(&tv_end, NULL);
    double elapsed = (tv_end.tv_sec - tv_start.tv_sec) +
                     (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;

    /* Cleanup */
    free(thread_ids);
    free(g_queue.tasks);
    pthread_mutex_destroy(&g_results.lock);
    pthread_mutex_destroy(&g_queue.lock);

    /* Print results */
    printf("\n");
    printf("\033[1;36m[*] Scan completed in %.2f seconds\033[0m\n", elapsed);
    printf("\033[1;36m[*] Ports scanned: %d\033[0m\n", total_ports);
    printf("\033[1;36m[*] Scan rate: %.2f ports/sec\033[0m\n\n", total_ports / elapsed);

    print_results();

    /* Machine-readable output (for Python integration) */
    printf("\033[1;36m[*] Machine-readable output:\033[0m\n");
    for (int i = 0; i < g_results.count; i++) {
        printf("%s:%d:%s\n", ip, g_results.results[i].port, g_results.results[i].service);
    }

    printf("\n\033[1;32m[+] Done!\033[0m\n");

    return 0;
}

/* ============================================= */
/* COMPILE INSTRUCTIONS */
/* ============================================= */

/*
 * To compile:
 *   gcc -O2 -pthread -o port_scanner port_scanner.c
 *
 * Or using clang:
 *   clang -O2 -pthread -o port_scanner port_scanner.c
 *
 * To run:
 *   ./port_scanner <host> [timeout] [threads] [start_port] [end_port]
 *
 * Examples:
 *   ./port_scanner 192.168.1.1
 *   ./port_scanner 192.168.1.1 2 200
 *   ./port_scanner scanme.nmap.org 3 100 1 1000
 */