/*
 * Secure IRC Client (Libevent + TLS) - ZIRC-IRC v2.5
 *
 * FULLY HARDENED - Maximum Security Configuration
 *
 * Compile on OpenBSD:
 * cc -o z25 z25.c \
 *    -I/usr/local/include -L/usr/local/lib \
 *    -lssl -lcrypto -levent_openssl -levent_core -levent_extra -levent \
 *    -lm -lpthread -lutil \
 *    -O2 -Wall -Wextra -Wpedantic -Werror \
 *    -fstack-protector-strong \
 *    -D_FORTIFY_SOURCE=2 \
 *    -fPIE -pie \
 *    -Wformat -Wformat-security \
 *    -Wl,-z,relro,-z,now
 *
 * Usage:
 *   ./z25 <server> <port> <nick> [prompt]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <limits.h>

/* OpenBSD Portability */
#ifdef __OpenBSD__
#include <unistd.h>
#else
#ifndef ENOSYS
#define ENOSYS 38
#endif
static inline int pledge(const char *p, const char *e) {
    (void)p; (void)e; errno = ENOSYS; return -1;
}
static inline int unveil(const char *p, const char *e) {
    (void)p; (void)e; errno = ENOSYS; return -1;
}
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>

/* Configuration Constants */
#define PING_INTERVAL_SEC           100
#define BUFFER_SIZE                 4096
#define CHANNEL                     "##"
#define IRC_MAX_MSG_LEN             512
#define MAX_NICK_LEN                63
#define MAX_RECONNECT_DELAY         60
#define MAX_RECONNECT_ATTEMPTS      10
#define CONNECTION_TIMEOUT_SEC      125
#define RATE_LIMIT_MSG_PER_SEC      25
#define MAX_PASSWORD_LEN            512

/* Global State */
static SSL_CTX *g_ssl_ctx = NULL;
static struct event_base *g_base = NULL;
static struct bufferevent *g_bev = NULL;
static struct bufferevent *g_stdin_bev = NULL;
static struct event *g_ping_timer = NULL;

/* Connection State */
static char g_server_host[256] = {0};
static char g_server_port[16] = {0};
static int g_reconnect_delay = 2;
static int g_reconnect_attempts = 0;
static int g_reconnect_pending = 0;

/* IRC State */
static int g_registered = 0;
static int g_joined = 0;
static char g_nick[MAX_NICK_LEN + 1] = {0};
static char *g_password = NULL;
static size_t g_password_len = 0;

/* Rate Limiter */
static time_t g_last_send_time = 0;
static int g_send_count = 0;

/* Cleanup Guard */
static volatile sig_atomic_t g_cleanup_in_progress = 0;

/* Ignore List */
static const char *g_ignore_list[] = {
    "MeowNexUS", "MeowNexu5", "MeowN3xUS", "eews", NULL
};

/* ANSI Colors */
#define ANSI_RESET          "\x1b[0m"
#define ANSI_BOLD           "\x1b[1m"
#define ANSI_ITALIC         "\x1b[3m"
#define ANSI_UNDER          "\x1b[4m"
#define ANSI_LIGHT_BLUE     "\x1b[94m"
#define ANSI_CYAN           "\x1b[36m"
#define ANSI_BRIGHT_BLUE    "\x1b[96m"
#define ANSI_BRIGHT_YELLOW  "\x1b[93m"
#define ANSI_MAGENTA        "\x1b[35m"
#define ANSI_BRIGHT_RED     "\x1b[91m"
#define ANSI_BRIGHT_GREEN   "\x1b[92m"
#define ANSI_GREY           "\x1b[90m"
#define ANSI_CREAM          "\x1b[97m"
#define ANSI_BELL           "\a"

/* IRC to 256-color mapping */
static const int g_irc_to_256[] = {
    15, 0, 19, 34, 196, 52, 127, 208, 226, 46, 51, 87, 75, 207, 244, 252
};

/* Function Prototypes */
static void handle_server_msg(char *line);
static void handle_user_input(char *line);
static void write_raw_line(const char *s);
static void sendln(const char *s);
static void print_ts(const char *prefix, const char *msg);
static char *get_secure_password(size_t *len_out);
static void cleanup_and_exit(int code);
static void deferred_cleanup_cb(evutil_socket_t fd, short ev, void *arg);
static int dial_server(const char *host, const char *port);
static void read_cb(struct bufferevent *bev, void *ctx);
static void stdin_read_cb(struct bufferevent *bev, void *ctx);
static void event_cb(struct bufferevent *bev, short events, void *ctx);
static void ping_cb(evutil_socket_t fd, short ev, void *arg);
static void reconnect_cb(evutil_socket_t fd, short ev, void *arg);
static void schedule_reconnect(void);
static int setup_unveil(void);
static int setup_ssl_context(void);
static int is_ignored(const char *nick);
static void secure_zero(void *ptr, size_t len);
static const char *get_channel_color(const char *channel);

/* SECURITY UTILITIES */

static const char *get_channel_color(const char *channel) {
    if (!channel) return ANSI_CREAM;
    
    /* Default channel (##) gets white */
    if (strcmp(channel, CHANNEL) == 0) {
        return ANSI_LIGHT_BLUE;
    }
    
    /* All other channels get grey */
    return ANSI_CREAM;
}
 
static void secure_zero(void *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

static int is_ignored(const char *nick) {
    if (!nick) return 0;
    
    for (size_t i = 0; g_ignore_list[i]; i++) {
        const char *a = nick;
        const char *b = g_ignore_list[i];
        
        while (*a && *b) {
            if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
                break;
            a++;
            b++;
        }
        
        if (*a == '\0' && *b == '\0')
            return 1;
    }
    return 0;
}

/*  CLEANUP AND SHUTDOWN  */

static void cleanup_and_exit(int code) {
    if (g_cleanup_in_progress) return;
    g_cleanup_in_progress = 1;

    fprintf(stderr, "\n*** [CLEANUP] Initiating shutdown (code: %d)...\n", code);

    if (g_ping_timer) {
        event_free(g_ping_timer);
        g_ping_timer = NULL;
    }

    if (g_stdin_bev) {
        bufferevent_free(g_stdin_bev);
        g_stdin_bev = NULL;
    }

    if (g_bev) {
        bufferevent_free(g_bev);
        g_bev = NULL;
    }

    if (g_base) {
        event_base_free(g_base);
        g_base = NULL;
    }

    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }

    if (g_password) {
        secure_zero(g_password, g_password_len);
        free(g_password);
        g_password = NULL;
        g_password_len = 0;
    }

    fprintf(stderr, "*** [CLEANUP] Shutdown complete.\n");
    exit(code);
}

static void cleanup_handler(void) {
    cleanup_and_exit(0);
}

static void deferred_cleanup_cb(evutil_socket_t fd, short ev, void *arg) {
    (void)fd; (void)ev;
    int exit_code = arg ? (int)(intptr_t)arg : 0;
    cleanup_and_exit(exit_code);
}

/* ========================================================================
 * SANDBOXING - unveil() and pledge()
 * ======================================================================== */

static int setup_unveil(void) {
#ifdef __OpenBSD__
    /* DNS resolution (critical for getaddrinfo) */
    if (unveil("/etc/resolv.conf", "r") == -1) {
        fprintf(stderr, "*** [ERROR] unveil /etc/resolv.conf: %s\n", strerror(errno));
        return -1;
    }
    fprintf(stderr, ANSI_BOLD ANSI_BRIGHT_GREEN "  * [UNVEIL] /etc/resolv.conf (r)\n" ANSI_RESET);

    /* Terminal for password input */
    if (unveil("/dev/tty", "rw") == -1) {
        fprintf(stderr, "*** [WARNING] unveil /dev/tty: %s\n", strerror(errno));
    } else {
        fprintf(stderr, ANSI_BOLD ANSI_BRIGHT_GREEN "  * [UNVEIL] /dev/tty (rw)\n" ANSI_RESET);
    }

    /* Lock filesystem */
    if (unveil(NULL, NULL) == -1) {
        fprintf(stderr, "*** [ERROR] unveil lock: %s\n", strerror(errno));
        return -1;
    }
    
    fprintf(stderr, ANSI_BOLD ANSI_BRIGHT_GREEN "   [UNVEIL] Filesystem locked\n");
    return 0;
#else
    fprintf(stderr, "  ℹ [UNVEIL] Not available on this platform\n" ANSI_RESET);
    return 0;
#endif
}

/* PASSWORD INPUT */

static char *get_secure_password(size_t *len_out) {
    struct termios old_term, new_term;
    char *buffer = NULL;

    buffer = calloc(1, MAX_PASSWORD_LEN);
    if (!buffer) {
        fprintf(stderr, "*** [ERROR] Password buffer allocation failed\n");
        return NULL;
    }

    if (tcgetattr(STDIN_FILENO, &old_term) == -1) {
        fprintf(stderr, "*** [ERROR] tcgetattr: %s\n", strerror(errno));
        free(buffer);
        return NULL;
    }

    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    new_term.c_lflag |= ECHONL;

    fprintf(stderr, "Authenticate to NickServ: ");
    fflush(stderr);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == -1) {
        fprintf(stderr, "*** [ERROR] tcsetattr: %s\n", strerror(errno));
        free(buffer);
        return NULL;
    }

    if (!fgets(buffer, MAX_PASSWORD_LEN, stdin)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "*** [ERROR] Password read failed\n");
        secure_zero(buffer, MAX_PASSWORD_LEN);
        free(buffer);
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[--len] = '\0';
    }

    if (len == 0) {
        fprintf(stderr, "*** [ERROR] Empty password\n");
        secure_zero(buffer, MAX_PASSWORD_LEN);
        free(buffer);
        return NULL;
    }

    *len_out = len;
    return buffer;
}

/* SSL CONTEXT INITIALIZATION */

static int setup_ssl_context(void) {
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Require TLS 1.2+ */
    if (SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION) == 0) {
        fprintf(stderr, "*** [WARNING] Failed to set TLS 1.2 minimum\n");
    }

    /* Strong cipher suite */
    if (SSL_CTX_set_cipher_list(g_ssl_ctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES128-GCM-SHA256:"
            "!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!SEED") == 0) {
        fprintf(stderr, "*** [WARNING] Failed to set cipher list\n");
    }

    /* Security options */
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    /* Load CA certificates BEFORE unveil */
    if (SSL_CTX_set_default_verify_paths(g_ssl_ctx) != 1) {
        fprintf(stderr, "*** [WARNING] Failed to load default CA paths\n");
    }
    
#ifdef __OpenBSD__
    if (SSL_CTX_load_verify_locations(g_ssl_ctx, "/etc/ssl/cert.pem", NULL) != 1) {
        fprintf(stderr, "*** [WARNING] Failed to load /etc/ssl/cert.pem\n");
    }
#endif

    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
    
    fprintf(stderr, ANSI_BOLD ANSI_BRIGHT_GREEN "   [SSL] Context initialized (TLS 1.2+, strong ciphers)\n" ANSI_RESET);
    return 0;
}

/* RECONNECTION LOGIC */

static void reconnect_cb(evutil_socket_t fd, short ev, void *arg) {
    (void)fd; (void)ev; (void)arg;

    fprintf(stderr, "*** [RECONNECT] Attempt %d/%d\n",
            g_reconnect_attempts + 1, MAX_RECONNECT_ATTEMPTS);

    g_reconnect_pending = 0;

    if (dial_server(g_server_host, g_server_port) < 0) {
        fprintf(stderr, "*** [RECONNECT] Failed\n");
    }
}

static void schedule_reconnect(void) {
    if (g_reconnect_pending) {
        fprintf(stderr, "*** [RECONNECT] Already scheduled\n");
        return;
    }

    if (g_bev) {
        bufferevent_free(g_bev);
        g_bev = NULL;
    }

    if (g_ping_timer) {
        event_free(g_ping_timer);
        g_ping_timer = NULL;
    }

    g_reconnect_pending = 1;
    g_reconnect_attempts++;

    if (g_reconnect_attempts > MAX_RECONNECT_ATTEMPTS) {
        fprintf(stderr, ANSI_BRIGHT_RED
                "*** [FATAL] Max reconnect attempts exceeded\n"
                ANSI_RESET);
        cleanup_and_exit(1);
        return;
    }

    struct timeval tv = {g_reconnect_delay, 0};

    fprintf(stderr, "*** [RECONNECT] Scheduling in %d seconds...\n", g_reconnect_delay);

    if (event_base_once(g_base, -1, EV_TIMEOUT, reconnect_cb, NULL, &tv) < 0) {
        fprintf(stderr, "*** [ERROR] Failed to schedule reconnect\n");
        cleanup_and_exit(1);
        return;
    }

    /* Exponential backoff */
    g_reconnect_delay = (g_reconnect_delay < MAX_RECONNECT_DELAY / 2) 
                        ? g_reconnect_delay * 2 
                        : MAX_RECONNECT_DELAY;
}

/* CONNECTION ESTABLISHMENT */

static int dial_server(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res = NULL;
    int sock = -1;
    SSL *ssl = NULL;

    if (!host || !port) {
        fprintf(stderr, "*** [BUG] dial_server: NULL parameters\n");
        return -1;
    }

    fprintf(stderr, "  ⇌ [CONNECT] %s:%s (attempt %d/%d)\n",
            host, port, g_reconnect_attempts + 1, MAX_RECONNECT_ATTEMPTS + 1);

    g_registered = 0;
    g_joined = 0;

    /* DNS resolution */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai_err = getaddrinfo(host, port, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "*** [DNS ERROR] %s\n", gai_strerror(gai_err));
        goto error;
    }

    /* Socket creation */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        fprintf(stderr, "*** [SOCKET ERROR] %s\n", strerror(errno));
        goto error;
    }

    /* TCP connection */
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "*** [CONNECT ERROR] %s\n", strerror(errno));
        goto error;
    }

    freeaddrinfo(res);
    res = NULL;

    /* SSL object */
    ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* SNI */
    if (!SSL_set_tlsext_host_name(ssl, host)) {
        fprintf(stderr, "*** [WARNING] Failed to set SNI\n");
    }

    /* Hostname verification */
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    if (!param || !X509_VERIFY_PARAM_set1_host(param, host, 0)) {
        fprintf(stderr, "*** [SSL ERROR] Hostname verification setup failed\n");
        goto error;
    }

    /* Create bufferevent */
    g_bev = bufferevent_openssl_socket_new(g_base, sock, ssl,
                                           BUFFEREVENT_SSL_CONNECTING,
                                           BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (!g_bev) {
        fprintf(stderr, "*** [ERROR] bufferevent creation failed\n");
        goto error;
    }

    /* Connection timeout */
    struct timeval timeout = {CONNECTION_TIMEOUT_SEC, 0};
    bufferevent_set_timeouts(g_bev, &timeout, &timeout);

    /* Callbacks */
    bufferevent_setcb(g_bev, read_cb, NULL, event_cb, NULL);
    
    if (bufferevent_enable(g_bev, EV_READ | EV_WRITE) != 0) {
        fprintf(stderr, "*** [ERROR] Failed to enable bufferevent\n");
        goto error;
    }

    fprintf(stderr,ANSI_BOLD ANSI_BRIGHT_GREEN "   [SSL] Handshake initiated\n" ANSI_RESET);
    return 0;

error:
    if (res) freeaddrinfo(res);
    if (sock >= 0) close(sock);
    if (ssl) SSL_free(ssl);
    if (g_bev) {
        bufferevent_free(g_bev);
        g_bev = NULL;
    }
    schedule_reconnect();
    return -1;
}

/* PING/PONG KEEPALIVE */

static void ping_cb(evutil_socket_t fd, short ev, void *arg) {
    (void)fd; (void)ev; (void)arg;
    write_raw_line("PING :keepalive");
}

/* MESSAGE SENDING */

static void write_raw_line(const char *s) {
    if (!s || !g_bev) return;

    char buf[IRC_MAX_MSG_LEN + 2];
    int n = snprintf(buf, sizeof(buf), "%.*s\r\n", 
                     IRC_MAX_MSG_LEN - 2, s);
    
    if (n < 0 || n >= (int)sizeof(buf)) {
        fprintf(stderr, "*** [ERROR] Message formatting failed\n");
        return;
    }

    if (bufferevent_write(g_bev, buf, (size_t)n) != 0) {
        fprintf(stderr, "*** [ERROR] Network write failed\n");
    }
}

static void sendln(const char *s) {
    if (!s) return;

    /* Rate limiting */
    time_t now = time(NULL);
    if (now != (time_t)-1) {
        if (now != g_last_send_time) {
            g_last_send_time = now;
            g_send_count = 0;
        }

        if (++g_send_count > RATE_LIMIT_MSG_PER_SEC) {
            printf(ANSI_BRIGHT_RED
                   "*** RATE LIMIT: '%.40s%s'\n" ANSI_RESET,
                   s, strlen(s) > 40 ? "..." : "");
            return;
        }
    }

    /* Sanitize */
    char clean[IRC_MAX_MSG_LEN];
    strncpy(clean, s, sizeof(clean) - 1);
    clean[sizeof(clean) - 1] = '\0';

    for (char *p = clean; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }

    write_raw_line(clean);
}

/* MESSAGE DISPLAY */

static void print_ts(const char *prefix, const char *msg) {
    char timebuf[16] = "------";
    time_t now = time(NULL);

    if (now != (time_t)-1) {
        struct tm *tm = localtime(&now);
        if (tm) {
            strftime(timebuf, sizeof(timebuf), "%H%M%S", tm);
        }
    }

    printf(ANSI_RESET "[" ANSI_LIGHT_BLUE "%s" ANSI_RESET "]" ANSI_RESET " %s", timebuf, prefix);

    /* IRC formatting to ANSI with nickname highlighting */
    size_t nick_len = strlen(g_nick);
    
    for (const char *p = msg; *p; p++) {
        unsigned char c = *p;

        /* Check for nickname mention (case-insensitive, word boundary) */
        if (nick_len > 0 && (p == msg || !isalnum((unsigned char)*(p-1)))) {
            int matches = 1;
            for (size_t i = 0; i < nick_len; i++) {
                if (tolower((unsigned char)p[i]) != tolower((unsigned char)g_nick[i])) {
                    matches = 0;
                    break;
                }
            }
            if (matches && !isalnum((unsigned char)p[nick_len])) {
                /* Highlight the nickname */
                printf(ANSI_BOLD ANSI_MAGENTA);
                for (size_t i = 0; i < nick_len; i++) {
                    putchar(p[i]);
                }
                printf(ANSI_RESET);
                p += nick_len - 1;
                continue;
            }
        }

        switch (c) {
            case 0x02: printf(ANSI_BOLD); break;
            case 0x1D: printf(ANSI_ITALIC); break;
            case 0x1F: printf(ANSI_UNDER); break;
            case 0x16:
            case 0x0F: printf(ANSI_RESET); break;

            case 0x03: {
                printf(ANSI_RESET);
                if (*(p+1) && isdigit(*(p+1))) {
                    p++;
                    int fg = *p - '0';
                    if (*(p+1) && isdigit(*(p+1))) {
                        fg = fg * 10 + (*(++p) - '0');
                    }
                    if (fg >= 0 && fg < 16) {
                        printf("\x1b[38;5;%dm", g_irc_to_256[fg]);
                    }
                    if (*(p+1) == ',' && *(p+2) && isdigit(*(p+2))) {
                        p += 2;
                        int bg = *p - '0';
                        if (*(p+1) && isdigit(*(p+1))) {
                            bg = bg * 10 + (*(++p) - '0');
                        }
                        if (bg >= 0 && bg < 16) {
                            printf("\x1b[48;5;%dm", g_irc_to_256[bg]);
                        }
                    }
                }
                break;
            }

            case 0x01:
                break;

            case '\x1b':
                fprintf(stderr, " [SECURITY] Dropped ANSI escape\n");
                while (*(p+1) && (*(p+1) >= 0x20 && *(p+1) <= 0x7E)) p++;
                break;

            default:
                if (c >= 0x20 || (c & 0x80)) {
                    putchar(c);
                }
        }
    }

    printf(ANSI_RESET "\n");
}

/* IRC PROTOCOL HANDLER */

static void handle_server_msg(char *line) {
    /* PING/PONG */
    if (strncmp(line, "PING ", 5) == 0) {
        char pong[512];
        snprintf(pong, sizeof(pong), "PONG %s", line + 5);
        write_raw_line(pong);
        return;
    }

    if (strstr(line, " PONG ")) return;

    /* PRIVMSG */
    char *privmsg = strstr(line, "PRIVMSG ");
    if (privmsg) {
        char *prefix = strchr(line, ':');
        if (!prefix) goto print_raw;

        char *target = privmsg + 8;
        char *target_end = strchr(target, ' ');
        char *message = target_end ? strchr(target_end, ':') : NULL;
        
        if (!message) message = "(no message)";
        else message++;

        /* Extract nickname */
        char nickname[MAX_NICK_LEN + 1] = {0};
        char *bang = strchr(prefix + 1, '!');
        size_t nick_len = bang ? (size_t)(bang - prefix - 1) : strlen(prefix + 1);
        
        if (nick_len > MAX_NICK_LEN) nick_len = MAX_NICK_LEN;
        strncpy(nickname, prefix + 1, nick_len);
        
        if (is_ignored(nickname)) return;

        /* Extract target */
        char target_buf[64] = "UNKNOWN";
        if (target_end) {
            size_t tlen = (size_t)(target_end - target);
            if (tlen > sizeof(target_buf) - 1) tlen = sizeof(target_buf) - 1;
            strncpy(target_buf, target, tlen);
            target_buf[tlen] = '\0';
        }

        int is_pm = (strcmp(target_buf, g_nick) == 0);
        int is_action = (strlen(message) >= 8 && message[0] == '\001' &&
                        strncmp(message + 1, "ACTION ", 7) == 0);

        char prefix_buf[256];

        if (is_action) {
            const char *action_msg = message + 8;
            static char action_clean[512];
            strncpy(action_clean, action_msg, sizeof(action_clean) - 1);
            action_clean[sizeof(action_clean) - 1] = '\0';
            
            size_t len = strlen(action_clean);
            if (len > 0 && action_clean[len - 1] == '\001') {
                action_clean[len - 1] = '\0';
            }
            
            snprintf(prefix_buf, sizeof(prefix_buf), 
               ANSI_RESET "[%s%s" ANSI_RESET "]" ANSI_RESET " * " ANSI_MAGENTA "%s" ANSI_RESET " ", 
                    get_channel_color(target_buf), target_buf, nickname);
            print_ts(prefix_buf, action_clean);
        } else if (is_pm) {
            printf(ANSI_BELL);
            snprintf(prefix_buf, sizeof(prefix_buf),
                    ANSI_BOLD ANSI_BRIGHT_YELLOW "[PM] " ANSI_RESET "<" ANSI_MAGENTA "%s" ANSI_RESET ">: ", nickname);
            print_ts(prefix_buf, message);
        } else {
            printf(ANSI_BELL);
            snprintf(prefix_buf, sizeof(prefix_buf), 
              ANSI_RESET "[%s%s" ANSI_RESET "]" ANSI_RESET " <" ANSI_LIGHT_BLUE "%s" ANSI_RESET ">: ", 
                    get_channel_color(target_buf), target_buf, nickname);
            print_ts(prefix_buf, message);
        }
        return;
    }

    /* Numeric responses */
    char *dup = strdup(line);
    if (!dup) goto print_raw;

    char *p = dup;
    if (*p == ':') {
        char *sp = strchr(p + 1, ' ');
        if (sp) p = sp + 1;
    }

    while (*p == ' ') p++;
    
    char *end = strchr(p, ' ');
    if (end) *end = '\0';

    if (strcmp(p, "001") == 0 && !g_registered) {
        g_registered = 1;
        fprintf(stderr, "   [IRC] Registered\n");

        if (g_password) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "PRIVMSG NickServ :IDENTIFY %s", g_password);
            write_raw_line(cmd);
            fprintf(stderr, "   [AUTH] NickServ identification sent\n");

            secure_zero(g_password, g_password_len);
            free(g_password);
            g_password = NULL;
            g_password_len = 0;
        }
    } else if (strcmp(p, "396") == 0 && !g_joined) {
        g_joined = 1;
        char joinbuf[256];
        snprintf(joinbuf, sizeof(joinbuf), "JOIN %s", CHANNEL);
        sendln(joinbuf);
        printf(ANSI_BOLD ANSI_BRIGHT_GREEN
               "   Cloak confirmed. Now joining channel %s\n" ANSI_RESET, CHANNEL);
    } else if (strcmp(p, "MODE") == 0 || strcmp(p, "JOIN") == 0 ||
               strcmp(p, "PART") == 0 || strcmp(p, "QUIT") == 0 ||
               strcmp(p, "NICK") == 0) {
        free(dup);
        return;
    }

    free(dup);

print_raw:
    print_ts(">> ", line);
}

/* USER INPUT HANDLER */

static void handle_user_input(char *line) {
    if (!line) return;

    size_t len = strlen(line);
    
    /* Length check */
    size_t overhead = 8 + strlen(CHANNEL) + 4;
    size_t max_payload = (IRC_MAX_MSG_LEN > overhead) ? (IRC_MAX_MSG_LEN - overhead) : 0;
    
    if (len > max_payload) {
        printf(ANSI_BRIGHT_RED
               "*** ERROR: Message too long (%zu > %zu)\n" ANSI_RESET,
               len, max_payload);
        return;
    }

    /* Commands */
    if (line[0] == '/') {
        if (strcasecmp(line, "/quit") == 0) {
            sendln("QUIT :Goodbye");
            printf("*** [IRC] Disconnecting...\n");
            
            struct timeval tv = {1, 0};
            if (event_base_once(g_base, -1, EV_TIMEOUT, deferred_cleanup_cb, NULL, &tv) < 0) {
                cleanup_and_exit(0);
            }
            return;
        }
        
        if (strcasecmp(line, "/help") == 0) {
            printf("\n" ANSI_BOLD "Commands:\n" ANSI_RESET);
            printf("  /JOIN #channel     - Join channel\n");
            printf("  /MSG nick message  - Private message\n");
            printf("  /MSG #chan message - Send to channel\n");
            printf("  /ME action         - Send action\n");
            printf("  /QUIT              - Disconnect\n");
            printf("  /HELP              - This help\n");
            printf("  /<raw>             - Send raw IRC command\n\n");
            return;
        }
 
        if (strncasecmp(line, "/join ", 6) == 0) {
            char *channel = line + 6;
            while (*channel == ' ') channel++;
            
            if (*channel) {
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "JOIN %s", channel);
                sendln(cmd);
                printf(ANSI_BOLD ANSI_BRIGHT_GREEN
                       "  ≻≻   Joining new channel %s\n" ANSI_RESET, channel);
            } else {
                printf("Usage: /JOIN #channel\n");
            }
            return;
        }
       
        if (strncasecmp(line, "/msg ", 5) == 0) {
            char *target = line + 5;
            char *msg = strchr(target, ' ');
            if (msg) {
                *msg++ = '\0';
                char cmd[BUFFER_SIZE];
                snprintf(cmd, sizeof(cmd), "PRIVMSG %s :%s", target, msg);
                sendln(cmd);
                
                char prefix[256];
                int is_channel = (target[0] == '#' || target[0] == '&');
                if (is_channel) {
                    snprintf(prefix, sizeof(prefix), 
                            ANSI_RESET "[%s%s" ANSI_CREAM "]" ANSI_RESET " <" ANSI_BRIGHT_GREEN "%s" ANSI_RESET ">: ",
                            get_channel_color(target), target, g_nick);
                } else {
                    snprintf(prefix, sizeof(prefix),
                            ANSI_BOLD ANSI_BRIGHT_YELLOW "[PM to %s]" ANSI_RESET " <" ANSI_BRIGHT_GREEN "%s" ANSI_RESET ">: ",
                            target, g_nick);
                }
                print_ts(prefix, msg);
            } else {
                printf("Usage: /MSG <nick|#channel> <message>\n");
            }
            return;
        }
        
        if (strncasecmp(line, "/me ", 4) == 0) {
            char *msg = line + 4;
            char cmd[BUFFER_SIZE];
            snprintf(cmd, sizeof(cmd), "PRIVMSG %s :\001ACTION %s\001", CHANNEL, msg);
            sendln(cmd);
            
            char prefix[256];
            snprintf(prefix, sizeof(prefix), 
                    ANSI_RESET "[%s%s" ANSI_CREAM "]" ANSI_RESET " * " ANSI_CREAM "%s" ANSI_RESET " ", 
                    get_channel_color(CHANNEL), CHANNEL, g_nick);
            print_ts(prefix, msg);
            return;
        }
        
        /* Raw command */
        sendln(line + 1);
        print_ts(">> ", line);
        return;
    }

    /* Regular message */
    char cmd[BUFFER_SIZE];
    snprintf(cmd, sizeof(cmd), "PRIVMSG %s :%s", CHANNEL, line);
    sendln(cmd);
    
    char prefix[256];
    snprintf(prefix, sizeof(prefix), 
            ANSI_RESET "[%s%s" ANSI_RESET "]" ANSI_RESET " <" ANSI_BRIGHT_YELLOW "%s" ANSI_RESET ">: ", 
            get_channel_color(CHANNEL), CHANNEL, g_nick);
    print_ts(prefix, line);
}

/* LIBEVENT CALLBACKS */

static void read_cb(struct bufferevent *bev, void *ctx) {
    (void)ctx;
    struct evbuffer *input = bufferevent_get_input(bev);
    if (!input) return;

    char *line;
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF))) {
        handle_server_msg(line);
        free(line);
    }
}

static void stdin_read_cb(struct bufferevent *bev, void *ctx) {
    (void)ctx;
    struct evbuffer *input = bufferevent_get_input(bev);
    if (!input) return;

    char *line;
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_LF))) {
        handle_user_input(line);
        secure_zero(line, strlen(line));
        free(line);
    }
}

static void event_cb(struct bufferevent *bev, short events, void *ctx) {
    (void)ctx;

    if (events & BEV_EVENT_CONNECTED) {
        SSL *ssl = bufferevent_openssl_get_ssl(bev);
        if (ssl) {
            long verify = SSL_get_verify_result(ssl);
            if (verify != X509_V_OK) {
                fprintf(stderr, ANSI_BRIGHT_RED
                        "*** [SECURITY] Certificate verification FAILED: %s\n"
                        ANSI_RESET, X509_verify_cert_error_string(verify));
                bufferevent_free(g_bev);
                g_bev = NULL;
                schedule_reconnect();
                return;
            }
            fprintf(stderr,ANSI_BOLD ANSI_BRIGHT_GREEN  "   [SSL] Certificate verified\n"ANSI_RESET);
        }

        fprintf(stderr,ANSI_BOLD ANSI_BRIGHT_GREEN "   [CONNECT] Secured connection established\n"ANSI_RESET);

        /* Reset reconnect state */
        g_reconnect_delay = 2;
        g_reconnect_attempts = 0;

        /* Stage 2 pledge (remove dns, keep inet for established connection) */
        int sandboxed = 0;
#ifdef __OpenBSD__
        if (pledge("stdio inet rpath tty", NULL) == -1) {
            if (errno != ENOSYS) {
                perror("*** [SANDBOX ERROR] pledge stage 2");
                cleanup_and_exit(1);
            }
        } else {
            sandboxed = 1;
            printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
                   "  ᚼ OpenBSD Sandboxing Active: pledge(stdio inet rpath tty)\n"
                   ANSI_RESET);
        }
#endif

        if (!sandboxed) {
            fprintf(stderr, ANSI_BRIGHT_RED
                    "  ⚠ Running UNSANDBOXED\n"
                    ANSI_RESET);
        }

        /* Setup keepalive ping */
        if (g_ping_timer) {
            event_free(g_ping_timer);
        }

        struct timeval tv = {PING_INTERVAL_SEC, 0};
        g_ping_timer = event_new(g_base, -1, EV_PERSIST | EV_TIMEOUT, ping_cb, NULL);
        if (g_ping_timer) {
            event_add(g_ping_timer, &tv);
        }

        /* IRC registration */
        char buf[256];
        snprintf(buf, sizeof(buf), "NICK %s", g_nick);
        sendln(buf);
        snprintf(buf, sizeof(buf), "USER %s 0 * :%s", g_nick, g_nick);
        sendln(buf);

    } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT)) {
        
        if (events & BEV_EVENT_TIMEOUT) {
            fprintf(stderr, "\n*** [TIMEOUT] Connection timed out\n");
        } else if (events & BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            fprintf(stderr, "\n*** [ERROR] %s\n", evutil_socket_error_to_string(err));

            unsigned long ssl_err;
            while ((ssl_err = bufferevent_get_openssl_error(bev))) {
                char err_buf[256];
                ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                fprintf(stderr, "*** [SSL ERROR] %s\n", err_buf);
            }
        } else {
            fprintf(stderr, "\n*** [EOF] Connection closed\n");
        }

        if (g_ping_timer) {
            event_free(g_ping_timer);
            g_ping_timer = NULL;
        }

        if (g_bev) {
            bufferevent_free(g_bev);
            g_bev = NULL;
        }

        schedule_reconnect();
    }
}

/* MAIN */

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server> <port> <nick> [prompt]\n", argv[0]);
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  %s irc.libera.chat 6697 mynick\n", argv[0]);
        fprintf(stderr, "  %s irc.libera.chat 6697 mynick prompt\n", argv[0]);
        return 1;
    }

    /* Initialize OpenSSL */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                          OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        fprintf(stderr, "*** [FATAL] OpenSSL initialization failed\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    atexit(cleanup_handler);

    /* Parse arguments */
    const char *server = argv[1];
    const char *port = argv[2];
    const char *nickname = argv[3];

    if (strlen(nickname) > MAX_NICK_LEN) {
        fprintf(stderr, "*** [ERROR] Nickname too long (max %d)\n", MAX_NICK_LEN);
        return 1;
    }

    strncpy(g_server_host, server, sizeof(g_server_host) - 1);
    strncpy(g_server_port, port, sizeof(g_server_port) - 1);
    strncpy(g_nick, nickname, sizeof(g_nick) - 1);

    /* Password handling */
    if (argc >= 5 && strcmp(argv[4], "prompt") == 0) {
        g_password = get_secure_password(&g_password_len);
        if (!g_password) {
            fprintf(stderr, "*** [ERROR] Password input failed\n");
            return 1;
        }
    }

    /* Banner */
    printf("\n");
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
           "════════════════════════════════════════════════════════\n"
           ANSI_RESET);
    printf(ANSI_BOLD "  ZIRC-IRC v2.2 - Fully Hardened IRC Client\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
           "════════════════════════════════════════════════════════\n"
           ANSI_RESET);
    printf("\n");
    printf(ANSI_BOLD "Security Features:\n" ANSI_RESET);
    printf(ANSI_BRIGHT_GREEN "   TLS 1.2+ with Certificate Verification\n" ANSI_RESET);
    printf(ANSI_BRIGHT_GREEN "   Memory Zeroization (OPENSSL_cleanse)\n" ANSI_RESET);
    printf(ANSI_BRIGHT_GREEN "   OpenBSD unveil() Filesystem Restrictions\n" ANSI_RESET);
    printf(ANSI_BRIGHT_GREEN "   OpenBSD pledge() System Call Filtering\n" ANSI_RESET);
    printf(ANSI_BRIGHT_GREEN "   Rate Limiting (%d msg/sec)\n" ANSI_RESET, RATE_LIMIT_MSG_PER_SEC);
    printf(ANSI_BRIGHT_GREEN "   Input Sanitization & ANSI Stripping\n" ANSI_RESET);
    printf(ANSI_BRIGHT_GREEN "   Automatic Reconnection (max %d)\n" ANSI_RESET, MAX_RECONNECT_ATTEMPTS);
    printf("\n");

    /* Initialize event base */
    g_base = event_base_new();
    if (!g_base) {
        fprintf(stderr, "*** [FATAL] libevent initialization failed\n");
        return 1;
    }

    /* Setup STDIN */
    if (evutil_make_socket_nonblocking(STDIN_FILENO) < 0) {
        fprintf(stderr, "*** [WARNING] Failed to set STDIN non-blocking\n");
    }

    g_stdin_bev = bufferevent_socket_new(g_base, STDIN_FILENO, BEV_OPT_DEFER_CALLBACKS);
    if (!g_stdin_bev) {
        fprintf(stderr, "*** [FATAL] STDIN setup failed\n");
        event_base_free(g_base);
        return 1;
    }

    bufferevent_setcb(g_stdin_bev, stdin_read_cb, NULL, NULL, NULL);
    bufferevent_enable(g_stdin_bev, EV_READ);

    /* Initialize SSL context (BEFORE unveil) */
    if (setup_ssl_context() < 0) {
        fprintf(stderr, "*** [FATAL] SSL context initialization failed\n");
        cleanup_and_exit(1);
    }

    /* Apply unveil (AFTER SSL certs loaded) */
    if (setup_unveil() < 0) {
        fprintf(stderr, "*** [WARNING] unveil setup failed\n");
    }

    /* Stage 1 pledge (before connection) */
#ifdef __OpenBSD__
    if (pledge("stdio inet dns rpath tty", NULL) == -1) {
        if (errno != ENOSYS) {
            perror("*** [FATAL] pledge stage 1 failed");
            cleanup_and_exit(1);
        }
    } else {
        printf(ANSI_BRIGHT_GREEN
               "   pledge('stdio inet dns rpath tty') applied\n"
               ANSI_RESET);
    }
#endif

    printf("\n");
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW "                    ▘      ▘    \n" ANSI_RESET);
    printf("  " ANSI_BOLD ANSI_BRIGHT_YELLOW"                ▀▌▌▛▘▛▘  ▌▛▘▛▘\n");
    printf("  " ANSI_BOLD ANSI_BRIGHT_YELLOW"                ▙▖▌▌ ▙▖  ▌▌ ▙▖\n");
    printf("                  Version Z.2.2 \n");
    printf("\n");
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
           "═══════════════════════════════════════════════════════════\n"
           ANSI_RESET);
    printf("\n");
    printf(ANSI_BOLD "Connecting to server: " ANSI_BRIGHT_YELLOW "%s:%s" ANSI_RESET "\n", server, port);
    printf(ANSI_BOLD "Connected as: " ANSI_BRIGHT_YELLOW "%s" ANSI_RESET "\n", g_nick);
    printf(ANSI_BOLD "Channel for Hard Chats: " ANSI_RESET "%s\n", CHANNEL);
    printf("\n");

    /* Initial connection */
    if (dial_server(g_server_host, g_server_port) < 0) {
        fprintf(stderr, "*** [WARNING] Initial connection failed, will retry\n");
    }

    /* Event loop */
    fprintf(stderr, "  ⟳ [EVENT LOOP] Starting...\n\n");
    int result = event_base_dispatch(g_base);

    if (result < 0) {
        fprintf(stderr, "*** [ERROR] Event loop failed\n");
        cleanup_and_exit(1);
    } else if (result == 1) {
        fprintf(stderr, "*** [INFO] No events registered\n");
    }

    cleanup_and_exit(0);
    return 0;
}
