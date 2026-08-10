/* runix-audit-broker entry point: acquire the listening AF_UNIX socket (systemd
 * socket activation, or --listen <path> as test process configuration),
 * reconstruct broker state from the sink, then run a single-process,
 * **non-blocking multiplexed** accept loop.
 *
 * The loop is a poll(2) reactor: every accepted connection is a non-blocking
 * state machine (receive one framed request, then send one framed response)
 * with its own ABSOLUTE monotonic deadline. No connection can block another, so
 * a slow or trickling client cannot monopolize the broker while other clients
 * wait behind it (the failure mode of a serialized one-connection-at-a-time
 * loop). Concurrency and per-uid concurrency are bounded, the receive/response
 * buffers are bounded, and every error/disconnect/timeout path frees the
 * connection's descriptor and buffers.
 *
 * The broker's state mutation (append + fsync) stays single-threaded and
 * serialized; only the network I/O is multiplexed. All tunables and both paths
 * are process configuration (CLI/env), never protocol input: a client can never
 * tell the broker where to write. */
#include "broker.h"
#include "json.h"
#include "peer.h"
#include "proto.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#define RAB_DEFAULT_MAX_CONNS 64u
#define RAB_DEFAULT_MAX_CONNS_PER_UID 16u
#define RAB_HARD_MAX_CONNS 4096u

typedef struct {
    const char *sink_path;
    const char *listen_path; /* NULL => systemd socket activation */
    int recv_timeout_ms;
    int send_timeout_ms;
    int idle_timeout_ms; /* <0 => never idle-exit (run until signalled) */
    int backlog;
    unsigned conn_max_per_uid; /* connection attempts per window (0 => off) */
    int conn_window_ms;
    unsigned max_conns;         /* global concurrent accepted-connection cap */
    unsigned max_conns_per_uid; /* per-uid concurrent accepted cap (0 => off) */
} main_cfg;

/* ephemeral per-uid connection-attempt limiter (not persisted; DoS defense) */
typedef struct conn_uid {
    uid_t uid;
    unsigned n;
    struct timespec start;
    struct conn_uid *next;
} conn_uid;

/* one multiplexed connection: receive a request frame, then send one response */
typedef enum { ST_RECV, ST_SEND } conn_state;

typedef struct {
    int fd; /* -1 = free slot */
    conn_state state;
    rab_actor actor;
    struct timespec deadline; /* absolute CLOCK_MONOTONIC; never reset by progress */
    /* receive */
    unsigned char hdr[5];
    size_t hdr_got;
    int have_len;
    uint32_t body_len;
    char *body;
    size_t body_got;
    /* send */
    unsigned char *out;
    size_t out_len;
    size_t out_sent;
} conn;

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

/* Milliseconds from `now` until absolute `dl` (negative if already past). */
static long long deadline_ms(const struct timespec *dl,
                             const struct timespec *now) {
    return (long long) (dl->tv_sec - now->tv_sec) * 1000LL +
           (long long) (dl->tv_nsec - now->tv_nsec) / 1000000LL;
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

/* ---- connection state machine ----------------------------------------- */

static void conn_close(conn *c) {
    if (c->fd >= 0) {
        close(c->fd);
    }
    free(c->body);
    free(c->out);
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

typedef enum {
    R_MORE,     /* would block; wait for the next POLLIN */
    R_CLOSE,    /* EOF/error/OOM: close silently (no reply guaranteed) */
    R_DONE,     /* a full frame is in c->body / c->body_len */
    R_BADVER,   /* version byte != 1 */
    R_TOOLARGE, /* length prefix exceeds the maximum */
    R_BADFRAME  /* EOF in the middle of the body */
} recv_result;

/* Read as much of the request frame as is available without blocking. The fd is
 * non-blocking; partial progress is retained across calls in *c. */
static recv_result conn_do_recv(conn *c) {
    while (c->hdr_got < sizeof c->hdr) {
        ssize_t r = read(c->fd, c->hdr + c->hdr_got, sizeof c->hdr - c->hdr_got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return R_MORE;
            }
            return R_CLOSE;
        }
        if (r == 0) {
            return R_CLOSE; /* EOF during the header: clean/partial disconnect */
        }
        c->hdr_got += (size_t) r;
    }
    if (!c->have_len) {
        if (c->hdr[0] != RAB_PROTO_VERSION) {
            return R_BADVER;
        }
        uint32_t n = ((uint32_t) c->hdr[1] << 24) | ((uint32_t) c->hdr[2] << 16) |
                     ((uint32_t) c->hdr[3] << 8) | (uint32_t) c->hdr[4];
        if (n > RAB_MAX_BODY) {
            return R_TOOLARGE;
        }
        c->body = malloc((size_t) n + 1);
        if (c->body == NULL) {
            return R_CLOSE; /* OOM: drop */
        }
        c->body_len = n;
        c->have_len = 1;
    }
    while (c->body_got < c->body_len) {
        ssize_t r =
            read(c->fd, c->body + c->body_got, c->body_len - c->body_got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return R_MORE;
            }
            return R_CLOSE;
        }
        if (r == 0) {
            return R_BADFRAME; /* EOF mid-body */
        }
        c->body_got += (size_t) r;
    }
    c->body[c->body_len] = '\0';
    return R_DONE;
}

/* Frame `resp` (malloc'd, consumed) into c->out and switch to the send phase
 * with a fresh absolute write deadline. 0 on success, -1 if it cannot be
 * queued (caller closes). */
static int conn_queue_response(conn *c, char *resp, const main_cfg *cfg) {
    if (resp == NULL) {
        return -1;
    }
    size_t len = strlen(resp);
    if (len > RAB_MAX_BODY) {
        free(resp);
        return -1;
    }
    c->out = malloc(5 + len);
    if (c->out == NULL) {
        free(resp);
        return -1;
    }
    c->out[0] = (unsigned char) RAB_PROTO_VERSION;
    c->out[1] = (unsigned char) ((len >> 24) & 0xff);
    c->out[2] = (unsigned char) ((len >> 16) & 0xff);
    c->out[3] = (unsigned char) ((len >> 8) & 0xff);
    c->out[4] = (unsigned char) (len & 0xff);
    memcpy(c->out + 5, resp, len);
    free(resp);
    c->out_len = 5 + len;
    c->out_sent = 0;
    c->state = ST_SEND;
    monotonic_plus(&c->deadline, cfg->send_timeout_ms);
    return 0;
}

/* Parse + handle the received frame and queue the response. On success c->state
 * becomes ST_SEND; otherwise it is left in ST_RECV and the caller closes. */
static void conn_handle(conn *c, rab_broker *b, const main_cfg *cfg) {
    rab_request req;
    const char *ec = NULL;
    char *resp = NULL;
    if (rab_parse_request(c->body, c->body_len, &req, &ec) != 0) {
        resp = rab_response_error(ec ? ec : "bad_json", "invalid request");
    } else {
        int rc = rab_broker_handle(b, &c->actor, &req, &resp);
        rab_request_free(&req);
        if (rc != 0 || resp == NULL) {
            free(resp);
            resp = rab_response_error("internal", "handler failure");
        }
    }
    free(c->body);
    c->body = NULL;
    (void) conn_queue_response(c, resp, cfg);
}

typedef enum { S_MORE, S_DONE, S_CLOSE } send_result;

static send_result conn_do_send(conn *c) {
    while (c->out_sent < c->out_len) {
        ssize_t w = write(c->fd, c->out + c->out_sent, c->out_len - c->out_sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return S_MORE;
            }
            return S_CLOSE;
        }
        c->out_sent += (size_t) w;
    }
    return S_DONE;
}

/* Count this uid's currently-active connections (per-uid concurrency cap). */
static unsigned uid_active(const conn *conns, unsigned max, uid_t uid) {
    unsigned n = 0;
    for (unsigned i = 0; i < max; i++) {
        if (conns[i].fd >= 0 && conns[i].actor.uid == uid) {
            n++;
        }
    }
    return n;
}

/* Accept every pending connection (bounded), admitting each into a free slot or
 * dropping it (peer unidentifiable, attempt-limited, at the per-uid or global
 * cap). Dropped connections are closed, never left half-open. */
static void accept_new(int lfd, conn *conns, unsigned max_conns, int *active,
                       const main_cfg *cfg, conn_uid **climiter) {
    for (;;) {
        if ((unsigned) *active >= max_conns) {
            break; /* global cap: stop admitting until a slot frees */
        }
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (cfd < 0) {
            break; /* drained (EAGAIN) or a transient error: retry next poll */
        }
        rab_actor actor;
        if (rab_peer_identity(cfd, &actor) != 0) {
            close(cfd); /* cannot identify the peer instance: fail closed */
            continue;
        }
        if (!conn_allowed(climiter, actor.uid, cfg)) {
            close(cfd); /* too many connection attempts from this uid */
            continue;
        }
        if (cfg->max_conns_per_uid != 0 &&
            uid_active(conns, max_conns, actor.uid) >= cfg->max_conns_per_uid) {
            close(cfd); /* this uid already holds its concurrency budget */
            continue;
        }
        unsigned s;
        for (s = 0; s < max_conns; s++) {
            if (conns[s].fd < 0) {
                break;
            }
        }
        if (s == max_conns) {
            close(cfd); /* no free slot (should not happen: active < cap) */
            break;
        }
        conn *c = &conns[s];
        memset(c, 0, sizeof *c);
        c->fd = cfd;
        c->actor = actor;
        c->state = ST_RECV;
        monotonic_plus(&c->deadline, cfg->recv_timeout_ms);
        (*active)++;
    }
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
    cfg.max_conns = (unsigned) env_int("RAB_MAX_CONNS", (int) RAB_DEFAULT_MAX_CONNS);
    cfg.max_conns_per_uid =
        (unsigned) env_int("RAB_MAX_CONNS_PER_UID", (int) RAB_DEFAULT_MAX_CONNS_PER_UID);
    if (cfg.max_conns < 1) {
        cfg.max_conns = 1;
    }
    if (cfg.max_conns > RAB_HARD_MAX_CONNS) {
        cfg.max_conns = RAB_HARD_MAX_CONNS;
    }

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

    conn *conns = calloc(cfg.max_conns, sizeof *conns);
    struct pollfd *pfds = malloc((size_t) (cfg.max_conns + 1) * sizeof *pfds);
    int *slotmap = malloc((size_t) (cfg.max_conns + 1) * sizeof *slotmap);
    if (conns == NULL || pfds == NULL || slotmap == NULL) {
        fprintf(stderr, "audit-broker: out of memory allocating loop state\n");
        free(conns);
        free(pfds);
        free(slotmap);
        rab_broker_close(b);
        return 1;
    }
    for (unsigned i = 0; i < cfg.max_conns; i++) {
        conns[i].fd = -1;
    }
    int active = 0;
    conn_uid *climiter = NULL;

    while (!g_stop) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        /* reap connections past their absolute deadline (slowloris defense: the
         * deadline is never reset by trickled progress). */
        for (unsigned i = 0; i < cfg.max_conns; i++) {
            if (conns[i].fd >= 0 && deadline_ms(&conns[i].deadline, &now) <= 0) {
                conn_close(&conns[i]);
                active--;
            }
        }

        /* build the poll set: the listener (only while below the global cap) and
         * every active connection, watching its current direction. */
        int nf = 0;
        if (!g_stop && active < (int) cfg.max_conns) {
            pfds[nf].fd = lfd;
            pfds[nf].events = POLLIN;
            pfds[nf].revents = 0;
            slotmap[nf] = -1;
            nf++;
        }
        long long nearest = -1;
        for (unsigned i = 0; i < cfg.max_conns; i++) {
            if (conns[i].fd < 0) {
                continue;
            }
            pfds[nf].fd = conns[i].fd;
            pfds[nf].events = (conns[i].state == ST_RECV) ? POLLIN : POLLOUT;
            pfds[nf].revents = 0;
            slotmap[nf] = (int) i;
            nf++;
            long long ms = deadline_ms(&conns[i].deadline, &now);
            if (ms < 0) {
                ms = 0;
            }
            if (nearest < 0 || ms < nearest) {
                nearest = ms;
            }
        }

        int timeout;
        if (active > 0) {
            timeout = (nearest > INT_MAX) ? INT_MAX : (int) nearest;
        } else {
            timeout = idle; /* idle-exit budget, or -1 to run until signalled */
        }

        int pr = poll(pfds, (nfds_t) nf, timeout);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            if (active == 0 && idle >= 0) {
                break; /* idle: exit so socket activation re-spawns on demand */
            }
            continue; /* a connection deadline fired; reaped at the top */
        }

        for (int k = 0; k < nf; k++) {
            if (pfds[k].revents == 0) {
                continue;
            }
            if (slotmap[k] == -1) {
                if (pfds[k].revents & POLLIN) {
                    accept_new(lfd, conns, cfg.max_conns, &active, &cfg,
                               &climiter);
                }
                continue;
            }
            conn *c = &conns[slotmap[k]];
            if (c->fd < 0) {
                continue; /* freed earlier in this pass */
            }
            if (c->state == ST_RECV && (pfds[k].revents & POLLIN)) {
                recv_result rr = conn_do_recv(c);
                if (rr == R_MORE) {
                    continue;
                }
                if (rr == R_DONE) {
                    conn_handle(c, b, &cfg);
                    if (c->state != ST_SEND) {
                        conn_close(c);
                        active--;
                    }
                    continue;
                }
                if (rr == R_BADVER || rr == R_TOOLARGE) {
                    const char *code = (rr == R_TOOLARGE) ? "too_large"
                                                          : "bad_frame";
                    const char *msg = (rr == R_TOOLARGE)
                                          ? "frame exceeds the maximum"
                                          : "bad version or truncated frame";
                    if (conn_queue_response(c, rab_response_error(code, msg),
                                            &cfg) != 0) {
                        conn_close(c);
                        active--;
                    }
                    continue;
                }
                /* R_CLOSE (disconnect) or R_BADFRAME (mid-body EOF): the peer is
                 * gone, so just close and reclaim the slot. */
                conn_close(c);
                active--;
                continue;
            }
            if (c->state == ST_SEND && (pfds[k].revents & POLLOUT)) {
                send_result sr = conn_do_send(c);
                if (sr == S_MORE) {
                    continue;
                }
                conn_close(c); /* one request per connection: done or errored */
                active--;
                continue;
            }
            if (pfds[k].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                conn_close(c);
                active--;
            }
        }
    }

    for (unsigned i = 0; i < cfg.max_conns; i++) {
        if (conns[i].fd >= 0) {
            conn_close(&conns[i]);
        }
    }
    free(conns);
    free(pfds);
    free(slotmap);
    conn_limiter_free(climiter);
    if (!activated && cfg.listen_path != NULL) {
        unlink(cfg.listen_path);
    }
    rab_broker_close(b);
    return 0;
}
