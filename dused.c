#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * x86_64 Linux syscall numbers
 *
 * Go (and Rust, etc.) bypass libc entirely and use raw syscalls.
 * For TCP, Go uses read/write on socket fds -- NOT sendto/recvfrom.
 * So we must:
 *   1. Track which fds are sockets (via socket/accept/accept4 return values)
 *   2. Count read/write bytes only when the fd is a socket
 *   3. Always count sendto/recvfrom/sendmsg/recvmsg bytes
 *   4. Trace all threads (Go is heavily multi-threaded via clone)
 */
#define NR_read      0
#define NR_write     1
#define NR_close     3
#define NR_readv    19
#define NR_writev   20
#define NR_socket   41
#define NR_accept   43
#define NR_sendto   44
#define NR_recvfrom 45
#define NR_sendmsg  46
#define NR_recvmsg  47
#define NR_accept4  288

/* ------------------------------------------------------------------ */
/* Socket fd tracking (threads share the fd table)                     */
/* ------------------------------------------------------------------ */
#define MAX_FDS 65536

static unsigned char sock_bitmap[MAX_FDS / 8];

static inline void fd_mark_socket(int fd) {
    if (fd >= 0 && fd < MAX_FDS)
        sock_bitmap[fd / 8] |= (unsigned char)(1u << (fd % 8));
}

static inline void fd_unmark_socket(int fd) {
    if (fd >= 0 && fd < MAX_FDS)
        sock_bitmap[fd / 8] &= (unsigned char)~(1u << (fd % 8));
}

static inline int fd_is_socket(int fd) {
    if (fd >= 0 && fd < MAX_FDS)
        return (sock_bitmap[fd / 8] >> (fd % 8)) & 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-thread syscall state                                            */
/* ------------------------------------------------------------------ */
#define MAX_THREADS 4096

struct thread_state {
    pid_t pid;
    int   in_syscall;      /* 1 = we are at syscall-exit next */
    int   pending_nr;      /* syscall number we entered */
    int   pending_fd;      /* fd argument (rdi) captured at entry */
};

static struct thread_state threads[MAX_THREADS];
static int nthreads = 0;

static struct thread_state *thread_get(pid_t pid) {
    for (int i = 0; i < nthreads; i++)
        if (threads[i].pid == pid)
            return &threads[i];
    if (nthreads >= MAX_THREADS)
        return NULL;
    struct thread_state *t = &threads[nthreads++];
    t->pid = pid;
    t->in_syscall = 0;
    t->pending_nr = 0;
    t->pending_fd = -1;
    return t;
}

static void thread_remove(pid_t pid) {
    for (int i = 0; i < nthreads; i++) {
        if (threads[i].pid == pid) {
            threads[i] = threads[--nthreads];
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Counters                                                            */
/* ------------------------------------------------------------------ */
static unsigned long long total_sent = 0;
static unsigned long long total_recv = 0;

static void print_totals(void) {
    fprintf(stderr,
        "dused: %llu bytes sent, %llu bytes received, %llu bytes total\n",
        total_sent, total_recv, total_sent + total_recv);
}

/* Should we track this syscall at entry? */
static inline int is_tracked(int nr) {
    switch (nr) {
    case NR_read: case NR_write: case NR_readv: case NR_writev:
    case NR_close:
    case NR_socket: case NR_accept: case NR_accept4:
    case NR_sendto: case NR_recvfrom: case NR_sendmsg: case NR_recvmsg:
        return 1;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        fprintf(stderr, "Measure total network I/O of any program (including Go).\n");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }

    if (child == 0) {
        /* Child: request tracing, stop so parent can set options, then exec */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(127);
        }
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        _exit(127);
    }

    /* Wait for child's initial SIGSTOP */
    int status;
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid (initial)");
        return 1;
    }

    /* Set ptrace options:
     *   TRACESYSGOOD  - set bit 7 of signal on syscall stops (easy to distinguish)
     *   TRACECLONE    - auto-attach to threads created by clone (Go uses many)
     *   TRACEFORK     - auto-attach to fork children
     *   TRACEVFORK    - auto-attach to vfork children
     *   TRACEEXEC     - get event on exec (so we don't misdeliver SIGTRAP)
     */
    long opts = PTRACE_O_TRACESYSGOOD
              | PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK
              | PTRACE_O_TRACEEXEC;

    if (ptrace(PTRACE_SETOPTIONS, child, 0, opts) != 0) {
        perror("ptrace(SETOPTIONS)");
        kill(child, SIGKILL);
        return 1;
    }

    thread_get(child);

    /* Resume child (it will exec the target command) */
    if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
        perror("ptrace(SYSCALL)");
        kill(child, SIGKILL);
        return 1;
    }

    int alive = 1;
    int exit_code = 0;

    while (alive > 0) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ---- Process/thread exited ---- */
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            thread_remove(pid);
            alive--;
            if (pid == child)
                exit_code = WIFEXITED(status)
                    ? WEXITSTATUS(status)
                    : 128 + WTERMSIG(status);
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;

        int sig   = WSTOPSIG(status);
        int event = (unsigned)status >> 16;

        /* ---- Ptrace event (clone/fork/exec) ---- */
        if (event) {
            if (event == PTRACE_EVENT_CLONE ||
                event == PTRACE_EVENT_FORK  ||
                event == PTRACE_EVENT_VFORK) {
                unsigned long new_pid = 0;
                ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid);
                thread_get((pid_t)new_pid);
                alive++;
            }
            /* PTRACE_EVENT_EXEC: nothing special, just resume */
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }

        /* ---- Syscall stop (sig == SIGTRAP | 0x80) ---- */
        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) {
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                continue;
            }

            struct thread_state *t = thread_get(pid);
            if (!t) {
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                continue;
            }

            if (t->in_syscall) {
                /* ---------- SYSCALL EXIT ---------- */
                long ret = (long)regs.rax;
                int  sc  = t->pending_nr;
                int  fd  = t->pending_fd;

                /* Track socket fd creation */
                if (sc == NR_socket || sc == NR_accept || sc == NR_accept4) {
                    if (ret >= 0)
                        fd_mark_socket((int)ret);
                }
                /* Track socket fd closure */
                else if (sc == NR_close) {
                    fd_unmark_socket(fd);
                }
                /* Count bytes on socket-specific calls (always a socket) */
                else if (ret > 0 && (sc == NR_sendto || sc == NR_sendmsg)) {
                    total_sent += (unsigned long long)ret;
                }
                else if (ret > 0 && (sc == NR_recvfrom || sc == NR_recvmsg)) {
                    total_recv += (unsigned long long)ret;
                }
                /* Count bytes on generic read/write only if fd is a socket */
                else if (ret > 0 && (sc == NR_write || sc == NR_writev)) {
                    if (fd_is_socket(fd))
                        total_sent += (unsigned long long)ret;
                }
                else if (ret > 0 && (sc == NR_read || sc == NR_readv)) {
                    if (fd_is_socket(fd))
                        total_recv += (unsigned long long)ret;
                }

                t->in_syscall = 0;
            } else {
                /* ---------- SYSCALL ENTRY ---------- */
                int nr = (int)regs.orig_rax;
                if (is_tracked(nr)) {
                    t->pending_nr = nr;
                    t->pending_fd = (int)regs.rdi;  /* 1st arg = fd */
                    t->in_syscall = 1;
                }
            }

            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }

        /* ---- Regular signal delivery ---- */
        /* Suppress SIGSTOP for newly auto-attached threads; deliver everything else */
        if (sig == SIGSTOP)
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        else
            ptrace(PTRACE_SYSCALL, pid, 0, sig);
    }

    print_totals();
    return exit_code;
}
