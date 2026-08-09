/* runix-audit-broker entry point: acquire the listening AF_UNIX socket (systemd
 * socket activation, or --listen <path> as test process configuration),
 * reconstruct broker state from the sink, then run a single-process, serialized
 * accept loop. Each connection gets an ABSOLUTE monotonic receive deadline and
 * a bounded write deadline (anti-slowloris), plus per-uid connection-attempt
 * limiting, so no unprivileged client can monopolize the loop.
 *
 * All tunables and both paths are process configuration (CLI/env), never
 * protocol input: a client can never tell the broker where to write. */
#include "broker.h"
#include "json.h"
#include "peer.h"
#include "proto.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SINK_PATH "/var/log/runix/audit.jsonl"

typedef struct {
    const char *sink_path;
    const char *listen_path; /* NULL => systemd socket activation */
    int recv_timeout_ms;
    int send_timeout_ms;
    int idle_timeout_ms; /* <0 => never idle-exit (run until signalled) */
    int backlog;
    unsigned conn_max_per_uid; /* connection attempts per window (0 => off) */
    int conn_window_ms;
} main_cfg;

/* ephemeral per-uid connection-attempt limiter (not persisted; DoS defense) */
typedef struct conn_uid {
    uid_t uid;
    unsigned n;
    struct timespec start;
    struct conn_uid *next;
} conn_uid;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void) sig;
    g_stop = 1;
}

static int env_int(const char *name, int fallback) {
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0') {
        return fallback;
    }
    char *endp = NULL;
    long n = strtol(v, &endp, 10);
    if (endp == v) {
        return fallback;
    }
    return (int) n;
}

static void monotonic_plus(struct timespec *out, int ms) {
    clock_gettime(CLOCK_MONOTONIC, out);
    out->tv_sec += ms / 1000;
    long ns = out->tv_nsec + (long) (ms % 1000) * 1000000L;
    out->tv_sec += ns / 1000000000L;
    out->tv_nsec = ns % 1000000000L;
}

static long long elapsed_ms(const struct timespec *from) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long) (now.tv_sec - from->tv_sec) * 1000LL +
           (long long) (now.tv_nsec - from->tv_nsec) / 1000000LL;
}

/* ---- listening socket -------------------------------------------------- */

/* systemd socket activation: the listening fd is passed as fd 3 with LISTEN_PID
 * / LISTEN_FDS in the environment. Returns the fd or -1 if not activated. */
static int activation_fd(void) {
    const char *lp = getenv("LISTEN_PID");
    const char *lf = getenv("LISTEN_FDS");
    if (lp == NULL || lf == NULL) {
        return -1;
    }
    if (strtol(lp, NULL, 10) != (long) getpid()) {
        return -1;
    }
    if (strtol(lf, NULL, 10) < 1) {
        return -1;
    }
    int fd = 3; /* SD_LISTEN_FDS_START */
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

/* Bind + listen on an AF_UNIX path (test process configuration). */
static int bind_listen(const char *path, int backlog) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof addr.sun_path) {
        close(fd);
        return -1;
    }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    unlink(path); /* clear a stale socket file */
    if (bind(fd, (struct sockaddr *) &addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    /* any local process may connect; identity comes from SO_PEERCRED */
    chmod(path, 0666);
    if (listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ---- connection-attempt limiter --------------------------------------- */

static int conn_allowed(conn_uid **head, uid_t uid, const main_cfg *cfg) {
    if (cfg->conn_max_per_uid == 0) {
        return 1;
    }
    conn_uid *u = NULL;
    for (conn_uid *c = *head; c != NULL; c = c->next) {
        if (c->uid == uid) {
            u = c;
            break;
        }
    }
    if (u == NULL) {
        u = calloc(1, sizeof *u);
        if (u == NULL) {
            return 0; /* fail closed */
        }
        u->uid = uid;
        u->next = *head;
        *head = u;
        clock_gettime(CLOCK_MONOTONIC, &u->start);
    }
    if (u->n == 0 || elapsed_ms(&u->start) > cfg->conn_window_ms) {
        clock_gettime(CLOCK_MONOTONIC, &u->start);
        u->n = 0;
    }
    u->n++;
    return u->n <= cfg->conn_max_per_uid;
}

static void conn_limiter_free(conn_uid *head) {
    while (head != NULL) {
        conn_uid *n = head->next;
        free(head);
        head = n;
    }
}

/* ---- serving one connection ------------------------------------------- */

static void send_err(int fd, const char *code, const char *msg,
                     const main_cfg *cfg) {
    char *resp = rab_response_error(code, msg);
    if (resp == NULL) {
        return;
    }
    struct timespec dl;
    monotonic_plus(&dl, cfg->send_timeout_ms);
    rab_write_frame_deadline(fd, resp, (uint32_t) strlen(resp), &dl);
    free(resp);
}

static void serve_connection(rab_broker *b, int cfd, const main_cfg *cfg,
                             conn_uid **climiter) {
    rab_actor actor;
    if (rab_peer_identity(cfd, &actor) != 0) {
        /* cannot identify the peer instance: fail closed, do not process */
        send_err(cfd, "internal", "peer identity unavailable", cfg);
        return;
    }
    if (!conn_allowed(climiter, actor.uid, cfg)) {
        /* too many connection attempts from this uid: drop, do not serve */
        return;
    }

    struct timespec recv_dl;
    monotonic_plus(&recv_dl, cfg->recv_timeout_ms);
    char *body = NULL;
    uint32_t len = 0;
    rab_frame_status fs = rab_read_frame_deadline(cfd, &body, &len, &recv_dl);
    switch (fs) {
    case RAB_FRAME_OK:
        break;
    case RAB_FRAME_TIMEOUT: /* slowloris: close and reclaim the loop */
    case RAB_FRAME_EOF:     /* client hung up */
    case RAB_FRAME_IO:
        return;
    case RAB_FRAME_TOO_LARGE:
        send_err(cfd, "too_large", "frame exceeds the maximum", cfg);
        return;
    case RAB_FRAME_BAD:
        send_err(cfd, "bad_frame", "bad version or truncated frame", cfg);
        return;
    }

    rab_request req;
    const char *ec = NULL;
    if (rab_parse_request(body, len, &req, &ec) != 0) {
        free(body);
        send_err(cfd, ec ? ec : "bad_json", "invalid request", cfg);
        return;
    }
    free(body);

    char *resp = NULL;
    if (rab_broker_handle(b, &actor, &req, &resp) != 0 || resp == NULL) {
        rab_request_free(&req);
        send_err(cfd, "internal", "handler failure", cfg);
        return;
    }
    rab_request_free(&req);

    struct timespec send_dl;
    monotonic_plus(&send_dl, cfg->send_timeout_ms);
    rab_write_frame_deadline(cfd, resp, (uint32_t) strlen(resp), &send_dl);
    free(resp);
}

/* ---- main -------------------------------------------------------------- */

int main(int argc, char **argv) {
    main_cfg cfg;
    cfg.sink_path = getenv("RAB_SINK_PATH");
    if (cfg.sink_path == NULL || cfg.sink_path[0] == '\0') {
        cfg.sink_path = DEFAULT_SINK_PATH;
    }
    cfg.listen_path = getenv("RAB_LISTEN_PATH");
    cfg.recv_timeout_ms = env_int("RAB_RECV_TIMEOUT_MS", 5000);
    cfg.send_timeout_ms = env_int("RAB_SEND_TIMEOUT_MS", 5000);
    cfg.idle_timeout_ms = env_int("RAB_IDLE_TIMEOUT_MS", 30000);
    cfg.backlog = env_int("RAB_LISTEN_BACKLOG", 16);
    cfg.conn_max_per_uid = (unsigned) env_int("RAB_CONN_MAX_PER_UID", 100);
    cfg.conn_window_ms = env_int("RAB_CONN_WINDOW_MS", 1000);

    /* minimal CLI: --listen/--sink override env (test process configuration) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            cfg.listen_path = argv[++i];
        } else if (strcmp(argv[i], "--sink") == 0 && i + 1 < argc) {
            cfg.sink_path = argv[++i];
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    rab_config bcfg;
    rab_config_defaults(&bcfg);
    const char *err = NULL;
    rab_broker *b = rab_broker_open(cfg.sink_path, &bcfg, NULL, NULL, &err);
    if (b == NULL) {
        fprintf(stderr, "audit-broker: cannot start: %s\n", err ? err : "?");
        return 1;
    }

    int lfd;
    int activated = 0;
    if (cfg.listen_path != NULL) {
        lfd = bind_listen(cfg.listen_path, cfg.backlog);
    } else {
        lfd = activation_fd();
        activated = (lfd >= 0);
    }
    if (lfd < 0) {
        fprintf(stderr, "audit-broker: no listening socket "
                        "(socket activation or --listen required)\n");
        rab_broker_close(b);
        return 1;
    }
    set_nonblock(lfd);

    /* Idle-exit is meaningful under socket activation (systemd re-spawns on the
     * next connection). Under --listen (tests) run until signalled. */
    int idle = activated ? cfg.idle_timeout_ms : -1;

    conn_uid *climiter = NULL;
    while (!g_stop) {
        struct pollfd pfd = {.fd = lfd, .events = POLLIN, .revents = 0};
        int pr = poll(&pfd, 1, idle);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            break; /* idle: exit so socket activation can re-spawn on demand */
        }
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (cfd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            continue; /* transient accept error: keep serving */
        }
        serve_connection(b, cfd, &cfg, &climiter);
        close(cfd);
    }

    conn_limiter_free(climiter);
    if (!activated && cfg.listen_path != NULL) {
        unlink(cfg.listen_path);
    }
    rab_broker_close(b);
    return 0;
}
