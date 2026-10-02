/*
 * banner_grabber.c
 * BlackHunter Pro - Service Banner Grabber
 * Grabs service banners from open ports for version detection
 * Academic Penetration Testing Tool - Isolated Lab Only
 *
 * Compile: gcc -O2 -pthread -o banner_grabber banner_grabber.c
 * Usage:   ./banner_grabber <host> <port> [timeout]
 *          ./banner_grabber <host> <start_port> <end_port> [timeout]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
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

#define MAX_THREADS 200
#define DEFAULT_TIMEOUT 3
#define DEFAULT_THREADS 50
#define BANNER_SIZE 4096
#define MAX_RESULTS 65536
#define PROBE_DELAY_US 100000 /* 100ms */

/* ============================================= */
/* DATA STRUCTURES */
/* ============================================= */

typedef struct {
    char host[256];
    int port;
    int timeout;
} GrabTask;

typedef struct {
    int port;
    char service[64];
    char banner[BANNER_SIZE];
    char version[256];
    int banner_len;
} BannerResult;

typedef struct {
    BannerResult results[MAX_RESULTS];
    int count;
    pthread_mutex_t lock;
} ResultList;

typedef struct {
    GrabTask *tasks;
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
/* SERVICE PROBES */
/* ============================================= */

typedef struct {
    int port;
    const char *service;
    const char *probe;    /* Data to send (NULL = just read) */
    int probe_len;        /* 0 = strlen(probe) */
} ServiceProbe;

static const ServiceProbe PROBES[] = {
    /* HTTP services */
    {80,    "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n", 0},
    {81,    "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {443,   "HTTPS",    NULL, 0},
    {8000,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {8001,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {8008,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {8080,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {8081,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {8443,  "HTTPS",    NULL, 0},
    {8888,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {9000,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {9090,  "HTTP",     "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", 0},
    {9200,  "HTTP",     "GET / HTTP/1.0\r\nHost: target\r\n\r\n", 0},

    /* Mail services */
    {25,    "SMTP",     "EHLO test\r\n", 0},
    {110,   "POP3",     "CAPA\r\n", 0},
    {143,   "IMAP",     "a001 CAPABILITY\r\n", 0},
    {465,   "SMTPS",    "EHLO test\r\n", 0},
    {587,   "SMTP",     "EHLO test\r\n", 0},
    {993,   "IMAPS",    NULL, 0},
    {995,   "POP3S",    NULL, 0},

    /* FTP */
    {21,    "FTP",      NULL, 0},

    /* SSH */
    {22,    "SSH",      NULL, 0},
    {2222,  "SSH",      NULL, 0},

    /* Telnet */
    {23,    "Telnet",   NULL, 0},

    /* Databases */
    {3306,  "MySQL",    NULL, 0},
    {5432,  "PostgreSQL", NULL, 0},
    {6379,  "Redis",    "INFO\r\n", 0},
    {27017, "MongoDB",  NULL, 0},
    {11211, "Memcached","stats\r\n", 0},

    /* Others */
    {873,   "Rsync",    "@RSYNCD: 31.0\r\n", 0},
    {1194,  "OpenVPN",  NULL, 0},
    {2375,  "Docker",   "GET /version HTTP/1.0\r\n\r\n", 0},
    {5984,  "CouchDB",  "GET / HTTP/1.0\r\n\r\n", 0},
    {11211, "Memcached","stats\r\n", 0},

    {0, NULL, NULL, 0}
};

/* ============================================= */
/* SERVICE LOOKUP */
/* ============================================= */

typedef struct {
    int port;
    const char *name;
} ServiceName;

static const ServiceName SERVICES[] = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
    {80,"HTTP"},{81,"HTTP-Alt"},{110,"POP3"},{111,"RPCbind"},
    {113,"Ident"},{119,"NNTP"},{123,"NTP"},{135,"MSRPC"},
    {137,"NetBIOS-NS"},{138,"NetBIOS-DGM"},{139,"NetBIOS-SSN"},
    {143,"IMAP"},{161,"SNMP"},{179,"BGP"},{194,"IRC"},
    {389,"LDAP"},{443,"HTTPS"},{445,"SMB"},{465,"SMTPS"},
    {500,"ISAKMP"},{514,"Syslog"},{515,"LPD"},{520,"RIP"},
    {548,"AFP"},{554,"RTSP"},{587,"SMTP-Submit"},{631,"IPP"},
    {636,"LDAPS"},{646,"LDP"},{873,"Rsync"},{990,"FTP-SSL"},
    {993,"IMAPS"},{995,"POP3S"},{1025,"NFS"},{1080,"SOCKS"},
    {1194,"OpenVPN"},{1433,"MSSQL"},{1434,"MSSQL-Browser"},
    {1521,"Oracle"},{1701,"L2TP"},{1720,"H.323"},{1723,"PPTP"},
    {1755,"MMS"},{1812,"RADIUS"},{1900,"SSDP"},{2000,"Cisco-SCCP"},
    {2049,"NFS"},{2082,"cPanel"},{2083,"cPanel-SSL"},{2086,"WHM"},
    {2087,"WHM-SSL"},{2222,"SSH-Alt"},{2323,"Telnet-Alt"},
    {2375,"Docker"},{2376,"Docker-SSL"},{3000,"Node.js"},
    {3128,"Squid-Proxy"},{3260,"iSCSI"},{3306,"MySQL"},
    {3389,"RDP"},{3690,"SVN"},{4000,"HTTP-Alt"},{4333,"mSQL"},
    {4443,"HTTPS-Alt"},{4444,"Metasploit"},{4505,"SaltStack"},
    {4506,"SaltStack"},{5000,"UPnP"},{5001,"HTTP-Alt"},
    {5005,"Java-RMI"},{5432,"PostgreSQL"},{5433,"PostgreSQL-Alt"},
    {5672,"AMQP"},{5900,"VNC"},{5901,"VNC-Alt"},{5984,"CouchDB"},
    {5985,"WinRM-HTTP"},{5986,"WinRM-HTTPS"},{6000,"X11"},
    {6379,"Redis"},{6443,"Kubernetes-API"},{6666,"IRC-Alt"},
    {7000,"Cassandra"},{7070,"HTTP-Alt"},{8000,"HTTP-Alt"},
    {8001,"HTTP-Alt"},{8008,"HTTP-Alt"},{8080,"HTTP-Proxy"},
    {8081,"HTTP-Alt"},{8086,"InfluxDB"},{8088,"HTTP-Alt"},
    {8090,"HTTP-Alt"},{8443,"HTTPS-Alt"},{8888,"HTTP-Alt"},
    {9000,"HTTP-Alt"},{9090,"HTTP-Alt"},{9200,"Elasticsearch"},
    {9300,"Elasticsearch"},{9443,"HTTPS-Alt"},{9999,"HTTP-Alt"},
    {10000,"Webmin"},{11211,"Memcached"},{15672,"RabbitMQ"},
    {27017,"MongoDB"},{27018,"MongoDB-Alt"},{50000,"SAP"},
    {50070,"Hadoop"},{50075,"Hadoop"},{50090,"Hadoop"},
    {0, NULL}
};

static const char* get_service_name(int port) {
    for (int i = 0; SERVICES[i].name != NULL; i++) {
        if (SERVICES[i].port == port) {
            return SERVICES[i].name;
        }
    }
    return "Unknown";
}

/* ============================================= */
/* GET SERVICE PROBE */
/* ============================================= */

static const ServiceProbe* get_probe(int port) {
    for (int i = 0; PROBES[i].service != NULL; i++) {
        if (PROBES[i].port == port) {
            return &PROBES[i];
        }
    }
    return NULL;
}

/* ============================================= */
/* RESOLVE HOST */
/* ============================================= */

static int resolve_host(const char *hostname, char *ip_out) {
    struct hostent *he;
    struct in_addr **addr_list;

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
/* SET SOCKET TIMEOUT */
/* ============================================= */

static void set_socket_timeout(int sock, int sec) {
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ============================================= */
/* CLEAN BANNER (remove non-printable, newlines) */
/* ============================================= */

static void clean_banner(char *banner, int len) {
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)banner[i];

        /* Replace newlines/tabs with space */
        if (c == '\r' || c == '\n' || c == '\t') {
            banner[i] = ' ';
        }
        /* Replace non-printable with dot */
        else if (c < 32 || c > 126) {
            banner[i] = '.';
        }
    }

    /* Trim trailing spaces */
    for (int i = len - 1; i >= 0 && banner[i] == ' '; i--) {
        banner[i] = '\0';
    }
}

/* ============================================= */
/* EXTRACT VERSION FROM BANNER */
/* ============================================= */

static void extract_version(const char *banner, int port, char *version_out) {
    version_out[0] = '\0';

    /* SSH version: SSH-2.0-OpenSSH_8.2p1 */
    if (strstr(banner, "SSH-") != NULL) {
        const char *start = strstr(banner, "SSH-");
        int j = 0;
        while (start[j] && start[j] != ' ' && j < 100) {
            version_out[j] = start[j];
            j++;
        }
        version_out[j] = '\0';
        return;
    }

    /* HTTP Server: Server: nginx/1.18.0 */
    const char *srv = strcasestr(banner, "Server:");
    if (srv != NULL) {
        srv += 7;
        while (*srv == ' ') srv++;
        int j = 0;
        while (srv[j] && srv[j] != '\r' && srv[j] != '\n' && j < 100) {
            version_out[j] = srv[j];
            j++;
        }
        version_out[j] = '\0';
        return;
    }

    /* FTP version */
    if (port == 21 && strstr(banner, "220") != NULL) {
        const char *start = banner;
        int j = 0;
        while (start[j] && start[j] != '\r' && start[j] != '\n' && j < 100) {
            version_out[j] = start[j];
            j++;
        }
        version_out[j] = '\0';
        return;
    }

    /* MySQL version: 5.7.38-log */
    if (port == 3306) {
        int j = 0;
        while (banner[j] && banner[j] != '\0' && j < 50) {
            version_out[j] = banner[j];
            j++;
        }
        version_out[j] = '\0';
        return;
    }

    /* Redis: redis_version:6.0.9 */
    if (port == 6379) {
        const char *rv = strstr(banner, "redis_version:");
        if (rv != NULL) {
            rv += 14;
            int j = 0;
            while (rv[j] && rv[j] != '\r' && rv[j] != '\n' && j < 50) {
                version_out[j] = rv[j];
                j++;
            }
            version_out[j] = '\0';
            return;
        }
    }

    /* Default: first line */
    int j = 0;
    while (banner[j] && banner[j] != '\r' && banner[j] != '\n' && j < 80) {
        version_out[j] = banner[j];
        j++;
    }
    version_out[j] = '\0';
}

/* ============================================= */
/* GRAB BANNER */
/* ============================================= */

static int grab_banner(const char *host, int port, int timeout,
                       char *banner_out, int *banner_len) {
    int sock;
    struct sockaddr_in target;
    struct timeval tv;
    char buffer[BANNER_SIZE];
    int total_bytes = 0;
    int bytes;

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    /* Setup target */
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, host, &target.sin_addr);

    /* Set timeout */
    set_socket_timeout(sock, timeout);

    /* Connect */
    if (connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(sock);
        return -1;
    }

    /* Get probe for this port */
    const ServiceProbe *probe = get_probe(port);

    if (probe != NULL && probe->probe != NULL) {
        /* Send probe */
        int probe_len = probe->probe_len > 0 ? probe->probe_len : strlen(probe->probe);
        send(sock, probe->probe, probe_len, 0);

        /* Wait for response */
        usleep(PROBE_DELAY_US);
    }

    /* Read banner (multiple reads for HTTP) */
    memset(buffer, 0, sizeof(buffer));

    while (total_bytes < BANNER_SIZE - 1) {
        bytes = recv(sock, buffer + total_bytes,
                     BANNER_SIZE - 1 - total_bytes, 0);

        if (bytes <= 0) break;

        total_bytes += bytes;

        /* For HTTP, we usually have enough after first read */
        if (total_bytes > 512) break;

        /* Check if we have complete response */
        if (strstr(buffer, "\r\n\r\n") != NULL) break;

        /* Short timeout for subsequent reads */
        tv.tv_sec = 0;
        tv.tv_usec = 200000; /* 200ms */
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    close(sock);

    if (total_bytes <= 0) return -1;

    buffer[total_bytes] = '\0';

    /* Clean banner */
    clean_banner(buffer, total_bytes);

    /* Copy to output */
    strncpy(banner_out, buffer, BANNER_SIZE - 1);
    banner_out[BANNER_SIZE - 1] = '\0';
    *banner_len = total_bytes;

    return 0;
}

/* ============================================= */
/* ADD RESULT */
/* ============================================= */

static void add_result(int port, const char *banner, int banner_len) {
    pthread_mutex_lock(&g_results.lock);

    if (g_results.count < MAX_RESULTS) {
        BannerResult *r = &g_results.results[g_results.count];
        r->port = port;
        strncpy(r->service, get_service_name(port), sizeof(r->service) - 1);
        r->service[sizeof(r->service) - 1] = '\0';

        strncpy(r->banner, banner, BANNER_SIZE - 1);
        r->banner[BANNER_SIZE - 1] = '\0';
        r->banner_len = banner_len;

        extract_version(banner, port, r->version);

        g_results.count++;
    }

    pthread_mutex_unlock(&g_results.lock);
}

/* ============================================= */
/* GET NEXT PORT */
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
    int banner_len = 0;

    while (g_running) {
        int port = get_next_port();
        if (port < 0) break;

        banner[0] = '\0';

        int result = grab_banner(host, port, g_timeout, banner, &banner_len);

        if (result == 0) {
            /* Color based on port */
            if (port == 21 || port == 23 || port == 445 || port == 3389) {
                printf("\033[1;31m");
            } else if (port == 22 || port == 3306 || port == 5432 ||
                       port == 6379 || port == 27017 || port == 11211) {
                printf("\033[1;33m");
            } else {
                printf("\033[1;32m");
            }

            printf("[+] Port %-5d | %-15s | %s\n",
                   port, get_service_name(port),
                   banner_len > 80 ? "(long banner)" : banner);
            printf("\033[0m");

            add_result(port, banner, banner_len);
        }
    }

    return NULL;
}

/* ============================================= */
/* PRINT USAGE */
/* ============================================= */

static void print_usage(const char *prog) {
    printf("BlackHunter Pro - Banner Grabber\n");
    printf("Usage: %s <host> <port> [timeout]\n", prog);
    printf("       %s <host> <start_port> <end_port> [timeout]\n", prog);
    printf("\n");
    printf("Arguments:\n");
    printf("  host       - Target hostname or IP\n");
    printf("  port       - Single port to scan\n");
    printf("  start_port - Start of port range\n");
    printf("  end_port   - End of port range\n");
    printf("  timeout    - Connection timeout (default: %d)\n", DEFAULT_TIMEOUT);
    printf("\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.1 80\n", prog);
    printf("  %s 192.168.1.1 80 443\n", prog);
    printf("  %s 192.168.1.1 1 1000 3\n", prog);
    printf("  %s example.com 22 5\n", prog);
    printf("\n");
}

/* ============================================= */
/* PRINT BANNER */
/* ============================================= */

static void print_banner(void) {
    printf("\n");
    printf("\033[1;33m");
    printf("  ██████╗  █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ \n");
    printf("  ██╔══██╗██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\n");
    printf("  ██████╔╝███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\n");
    printf("  ██╔══██╗██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\n");
    printf("  ██████╔╝██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\n");
    printf("  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n");
    printf("\033[0m");
    printf("\033[1;36m");
    printf("                  Service Banner Grabber\n");
    printf("                  Academic Penetration Testing Tool\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* PRINT RESULTS TABLE */
/* ============================================= */

static void print_results(void) {
    if (g_results.count == 0) {
        printf("\n\033[1;33m[!] No banners grabbed\033[0m\n");
        return;
    }

    printf("\n\033[1;32m[+] Grabbed %d banners:\033[0m\n\n", g_results.count);

    /* Sort by port */
    for (int i = 0; i < g_results.count - 1; i++) {
        for (int j = i + 1; j < g_results.count; j++) {
            if (g_results.results[i].port > g_results.results[j].port) {
                BannerResult temp = g_results.results[i];
                g_results.results[i] = g_results.results[j];
                g_results.results[j] = temp;
            }
        }
    }

    printf("\033[1;36m");
    printf("╔══════════╦══════════════════╦═══════════════════════════════════════════════╗\n");
    printf("║   PORT   ║     SERVICE      ║              BANNER / VERSION                 ║\n");
    printf("╠══════════╬══════════════════╬═══════════════════════════════════════════════╣\n");
    printf("\033[0m");

    for (int i = 0; i < g_results.count; i++) {
        BannerResult *r = &g_results.results[i];

        /* Color */
        if (r->port == 21 || r->port == 23 || r->port == 445 || r->port == 3389) {
            printf("\033[1;31m");
        } else if (r->port == 22 || r->port == 3306 || r->port == 5432 ||
                   r->port == 6379 || r->port == 27017) {
            printf("\033[1;33m");
        } else {
            printf("\033[1;32m");
        }

        printf("║ %-8d ║ %-16s ║ ", r->port, r->service);

        if (r->banner[0] != '\0') {
            char short_banner[46];
            strncpy(short_banner, r->banner, 42);
            short_banner[42] = '\0';
            if (strlen(r->banner) > 42) {
                strcat(short_banner, "...");
            }
            printf("%-45s", short_banner);
        } else {
            printf("%-45s", "-");
        }

        printf(" ║\n");
        printf("\033[0m");
    }

    printf("\033[1;36m");
    printf("╚══════════╩══════════════════╩═══════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* SIGNAL HANDLER */
/* ============================================= */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n\033[1;33m[!] Interrupted by user\033[0m\n");
}

/* ============================================= */
/* MAIN */
/* ============================================= */

int main(int argc, char *argv[]) {
    char ip[64];
    const char *host;
    int start_port, end_port;
    int total_ports;
    int threads = DEFAULT_THREADS;

    print_banner();

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    host = argv[1];

    /* Parse port range */
    if (argc == 3) {
        /* Single port */
        start_port = atoi(argv[2]);
        end_port = start_port;
        if (argc >= 4) g_timeout = atoi(argv[3]);
    } else if (argc >= 4) {
        /* Port range */
        start_port = atoi(argv[2]);
        end_port = atoi(argv[3]);
        if (argc >= 5) g_timeout = atoi(argv[4]);
    } else {
        print_usage(argv[0]);
        return 1;
    }

    /* Validate */
    if (start_port < 1 || start_port > 65535) {
        fprintf(stderr, "\033[1;31m[!] Invalid start port\033[0m\n");
        return 1;
    }

    if (end_port < 1 || end_port > 65535) {
        fprintf(stderr, "\033[1;31m[!] Invalid end port\033[0m\n");
        return 1;
    }

    if (start_port > end_port) {
        int tmp = start_port;
        start_port = end_port;
        end_port = tmp;
    }

    if (g_timeout < 1) g_timeout = DEFAULT_TIMEOUT;

    /* Resolve host */
    printf("\033[1;36m[*] Resolving %s...\033[0m\n", host);

    if (resolve_host(host, ip) < 0) {
        fprintf(stderr, "\033[1;31m[!] Failed to resolve host\033[0m\n");
        return 1;
    }

    printf("\033[1;32m[+] IP: %s\033[0m\n", ip);
    printf("\033[1;36m[*] Port range: %d-%d\033[0m\n", start_port, end_port);
    printf("\033[1;36m[*] Timeout: %d second(s)\033[0m\n", g_timeout);

    total_ports = end_port - start_port + 1;
    printf("\033[1;36m[*] Total ports: %d\033[0m\n", total_ports);

    /* Adjust threads for small ranges */
    if (total_ports < threads) {
        threads = total_ports > 0 ? total_ports : 1;
    }

    printf("\033[1;36m[*] Threads: %d\033[0m\n", threads);
    printf("\033[1;36m[*] Grabbing banners...\033[0m\n\n");

    /* Initialize */
    memset(&g_results, 0, sizeof(g_results));
    pthread_mutex_init(&g_results.lock, NULL);

    g_queue.tasks = (GrabTask *)malloc(sizeof(GrabTask) * total_ports);
    if (g_queue.tasks == NULL) {
        fprintf(stderr, "\033[1;31m[!] Memory allocation failed\033[0m\n");
        return 1;
    }

    for (int i = 0; i < total_ports; i++) {
        g_queue.tasks[i].port = start_port + i;
        g_queue.tasks[i].timeout = g_timeout;
    }

    g_queue.task_count = total_ports;
    g_queue.next_task = 0;
    g_queue.results = &g_results;
    pthread_mutex_init(&g_queue.lock, NULL);

    /* Signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Start timer */
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);

    /* Create threads */
    pthread_t *thread_ids = (pthread_t *)malloc(sizeof(pthread_t) * threads);
    if (thread_ids == NULL) {
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

    /* Wait for threads */
    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    /* Calculate time */
    gettimeofday(&tv_end, NULL);
    double elapsed = (tv_end.tv_sec - tv_start.tv_sec) +
                     (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;

    /* Cleanup */
    free(thread_ids);
    free(g_queue.tasks);
    pthread_mutex_destroy(&g_results.lock);
    pthread_mutex_destroy(&g_queue.lock);

    /* Print results */
    printf("\n\033[1;36m[*] Completed in %.2f seconds\033[0m\n", elapsed);
    printf("\033[1;36m[*] Banners grabbed: %d\033[0m\n", g_results.count);

    print_results();

    /* Machine-readable output */
    printf("\033[1;36m[*] Machine-readable output:\033[0m\n");
    for (int i = 0; i < g_results.count; i++) {
        BannerResult *r = &g_results.results[i];
        printf("%s:%d:%s:%s\n", ip, r->port, r->service, r->version);
    }

    printf("\n\033[1;32m[+] Done!\033[0m\n");
    return 0;
}

/* ============================================= */
/* COMPILE INSTRUCTIONS */
/* ============================================= */

/*
 * Compile:
 *   gcc -O2 -pthread -o banner_grabber banner_grabber.c
 *   clang -O2 -pthread -o banner_grabber banner_grabber.c
 *
 * Usage:
 *   ./banner_grabber <host> <port> [timeout]
 *   ./banner_grabber <host> <start_port> <end_port> [timeout]
 *
 * Examples:
 *   ./banner_grabber 192.168.1.1 80
 *   ./banner_grabber 192.168.1.1 80 443
 *   ./banner_grabber 192.168.1.1 1 1000 3
 *   ./banner_grabber scanme.nmap.org 22 5
 */