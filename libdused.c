#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static _Atomic unsigned long long total_sent = 0;
static _Atomic unsigned long long total_recv = 0;
static int atexit_registered = 0;
static pthread_mutex_t atexit_mutex = PTHREAD_MUTEX_INITIALIZER;

static void print_usage(void) {
    unsigned long long sent = __atomic_load_n(&total_sent, __ATOMIC_RELAXED);
    unsigned long long recv = __atomic_load_n(&total_recv, __ATOMIC_RELAXED);
    fprintf(stderr, "\ndused: total network I/O: %llu bytes sent, %llu bytes received (%llu bytes total)\n",
            (unsigned long long)sent, (unsigned long long)recv, (unsigned long long)(sent + recv));
}

static void register_atexit_once(void) {
    pthread_mutex_lock(&atexit_mutex);
    if (!atexit_registered) {
        atexit_registered = 1;
        atexit(print_usage);
    }
    pthread_mutex_unlock(&atexit_mutex);
}

typedef ssize_t (*send_t)(int, const void *, size_t, int);
typedef ssize_t (*recv_t)(int, void *, size_t, int);
typedef ssize_t (*sendto_t)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_t)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*sendmsg_t)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_t)(int, struct msghdr *, int);

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    static send_t real_send;
    if (!real_send)
        real_send = (send_t)dlsym(RTLD_NEXT, "send");
    register_atexit_once();
    ssize_t n = real_send(sockfd, buf, len, flags);
    if (n > 0)
        __atomic_fetch_add(&total_sent, (unsigned long long)n, __ATOMIC_RELAXED);
    return n;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    static recv_t real_recv;
    if (!real_recv)
        real_recv = (recv_t)dlsym(RTLD_NEXT, "recv");
    register_atexit_once();
    ssize_t n = real_recv(sockfd, buf, len, flags);
    if (n > 0)
        __atomic_fetch_add(&total_recv, (unsigned long long)n, __ATOMIC_RELAXED);
    return n;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    static sendto_t real_sendto;
    if (!real_sendto)
        real_sendto = (sendto_t)dlsym(RTLD_NEXT, "sendto");
    register_atexit_once();
    ssize_t n = real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (n > 0)
        __atomic_fetch_add(&total_sent, (unsigned long long)n, __ATOMIC_RELAXED);
    return n;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    static recvfrom_t real_recvfrom;
    if (!real_recvfrom)
        real_recvfrom = (recvfrom_t)dlsym(RTLD_NEXT, "recvfrom");
    register_atexit_once();
    ssize_t n = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (n > 0)
        __atomic_fetch_add(&total_recv, (unsigned long long)n, __ATOMIC_RELAXED);
    return n;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    static sendmsg_t real_sendmsg;
    if (!real_sendmsg)
        real_sendmsg = (sendmsg_t)dlsym(RTLD_NEXT, "sendmsg");
    register_atexit_once();
    ssize_t n = real_sendmsg(sockfd, msg, flags);
    if (n > 0)
        __atomic_fetch_add(&total_sent, (unsigned long long)n, __ATOMIC_RELAXED);
    return n;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    static recvmsg_t real_recvmsg;
    if (!real_recvmsg)
        real_recvmsg = (recvmsg_t)dlsym(RTLD_NEXT, "recvmsg");
    register_atexit_once();
    ssize_t n = real_recvmsg(sockfd, msg, flags);
    if (n > 0)
        __atomic_fetch_add(&total_recv, (unsigned long long)n, __ATOMIC_RELAXED);
    return n;
}
