//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Xcode's Archive builds with Xcode's Package support struggle with empty .c files
// (https://bugs.swift.org/browse/SR-12939).
void CNIOLinux_i_do_nothing_just_working_around_a_darwin_toolchain_bug2(void) {}

#ifdef __linux__

#define _GNU_SOURCE
#include <CNIOLinux.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>

// io_uring

// local typedefs for readability of function pointers
// these should match the signatures in liburing.h
typedef struct io_uring_probe *(*io_uring_get_probe_ring_fp)(struct io_uring *ring);
typedef struct io_uring_probe *(*io_uring_get_probe_fp)(void);
typedef void (*io_uring_free_probe_fp)(struct io_uring_probe *probe);
typedef int (*io_uring_queue_init_params_fp)(unsigned entries, struct io_uring *ring,
    struct io_uring_params *p);
typedef int (*io_uring_queue_init_fp)(unsigned entries, struct io_uring *ring,
    unsigned flags);
typedef int (*io_uring_queue_mmap_fp)(int fd, struct io_uring_params *p,
    struct io_uring *ring);
typedef int (*io_uring_ring_dontfork_fp)(struct io_uring *ring);
typedef void (*io_uring_queue_exit_fp)(struct io_uring *ring);
typedef unsigned (*io_uring_peek_batch_cqe_fp)(struct io_uring *ring,
    struct io_uring_cqe **cqes, unsigned count);
typedef int (*io_uring_wait_cqes_fp)(struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr, unsigned wait_nr,
    struct __kernel_timespec *ts, sigset_t *sigmask);
typedef int (*io_uring_wait_cqe_timeout_fp)(struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr, struct __kernel_timespec *ts);
typedef int (*io_uring_submit_fp)(struct io_uring *ring);
typedef int (*io_uring_submit_and_wait_fp)(struct io_uring *ring, unsigned wait_nr);
typedef struct io_uring_sqe *(*io_uring_get_sqe_fp)(struct io_uring *ring);
typedef int (*io_uring_register_buffers_fp)(struct io_uring *ring,
                    const struct iovec *iovecs,
                    unsigned nr_iovecs);
typedef int (*io_uring_unregister_buffers_fp)(struct io_uring *ring);
typedef int (*io_uring_register_files_fp)(struct io_uring *ring, const int *files,
                    unsigned nr_files);
typedef int (*io_uring_unregister_files_fp)(struct io_uring *ring);
typedef int (*io_uring_register_files_update_fp)(struct io_uring *ring, unsigned off,
                    int *files, unsigned nr_files);
typedef int (*io_uring_register_eventfd_fp)(struct io_uring *ring, int fd);
typedef int (*io_uring_register_eventfd_async_fp)(struct io_uring *ring, int fd);
typedef int (*io_uring_unregister_eventfd_fp)(struct io_uring *ring);
typedef int (*io_uring_register_probe_fp)(struct io_uring *ring,
                    struct io_uring_probe *p, unsigned nr);
typedef int (*io_uring_register_personality_fp)(struct io_uring *ring);
typedef int (*io_uring_unregister_personality_fp)(struct io_uring *ring, int id);
typedef int (*io_uring_register_restrictions_fp)(struct io_uring *ring,
                      struct io_uring_restriction *res,
                      unsigned int nr_res);
typedef int (*io_uring_enable_rings_fp)(struct io_uring *ring);
typedef int (*__io_uring_sqring_wait_fp)(struct io_uring *ring);
typedef int (*__io_uring_get_cqe_fp)(struct io_uring *ring,
                  struct io_uring_cqe **cqe_ptr, unsigned submit,
                  unsigned wait_nr, sigset_t *sigmask);

// local static struct holding resolved function pointers for liburing
static struct _liburing_functions_t
{
    io_uring_get_probe_ring_fp io_uring_get_probe_ring;
    io_uring_get_probe_fp io_uring_get_probe;
    io_uring_free_probe_fp io_uring_free_probe;
    io_uring_queue_init_params_fp io_uring_queue_init_params;
    io_uring_queue_init_fp io_uring_queue_init;
    io_uring_queue_mmap_fp io_uring_queue_mmap;
    io_uring_ring_dontfork_fp io_uring_ring_dontfork;
    io_uring_queue_exit_fp io_uring_queue_exit;
    io_uring_peek_batch_cqe_fp io_uring_peek_batch_cqe;
    io_uring_wait_cqes_fp io_uring_wait_cqes;
    io_uring_wait_cqe_timeout_fp io_uring_wait_cqe_timeout;
    io_uring_submit_fp io_uring_submit;
    io_uring_submit_and_wait_fp io_uring_submit_and_wait;
    io_uring_get_sqe_fp io_uring_get_sqe;
    io_uring_register_buffers_fp io_uring_register_buffers;
    io_uring_unregister_buffers_fp io_uring_unregister_buffers;
    io_uring_register_files_fp io_uring_register_files;
    io_uring_unregister_files_fp io_uring_unregister_files;
    io_uring_register_files_update_fp io_uring_register_files_update;
    io_uring_register_eventfd_fp io_uring_register_eventfd;
    io_uring_register_eventfd_async_fp io_uring_register_eventfd_async;
    io_uring_unregister_eventfd_fp io_uring_unregister_eventfd;
    io_uring_register_probe_fp io_uring_register_probe;
    io_uring_register_personality_fp io_uring_register_personality;
    io_uring_unregister_personality_fp io_uring_unregister_personality;
//    io_uring_register_restrictions_fp io_uring_register_restrictions;
//    io_uring_enable_rings_fp io_uring_enable_rings;
    __io_uring_sqring_wait_fp __io_uring_sqring_wait;
    __io_uring_get_cqe_fp __io_uring_get_cqe;
} liburing_functions;

// dynamically load liburing and resolve symbols. Should be called once before using io_uring.
// returns 0 on successful loading and resolving of functions, otherwise error

#define _DL_RESOLVE(symbol) \
    liburing_functions.symbol = (symbol ## _fp) dlsym(dl_handle, #symbol);  \
    if ((err = dlerror()) != NULL) {  \
        printf("WARNING: Failed to resolve " #symbol " from liburing, falling back on epoll()\n");  \
        (void) dlclose(dl_handle); \
        return -1;  \
    }

/*\
    else {  \
        printf("Resolved "  #symbol " from liburing, %p\n", liburing_functions.symbol);  \
    }
*/

int CNIOLinux_io_uring_load()
{
    void *dl_handle;
    const char *err;
    
        // fail if we didn't link with actual development headers
        // possibly warn here that someone tried to enable uring
        // while we hadn't compiled with the real headers
#ifdef C_NIO_LIBURING_DISABLED
    return -1;
#endif
    
    dlerror(); // canonical way of clearing dlerror
    dl_handle = dlopen("liburing.so", RTLD_LAZY);
    if (((err = dlerror()) != NULL) || !dl_handle) {
        printf("WARNING: Failed to load liburing.so, using epoll() instead. [%s] [%p]\n", err?err:"Unknown reason", dl_handle);
        return -1;
    }
    
        // try to resolve all symbols we need
    _DL_RESOLVE(io_uring_get_probe_ring);
    _DL_RESOLVE(io_uring_get_probe);
    _DL_RESOLVE(io_uring_free_probe);
    _DL_RESOLVE(io_uring_queue_init_params);
    _DL_RESOLVE(io_uring_queue_init);
    _DL_RESOLVE(io_uring_queue_mmap);
    _DL_RESOLVE(io_uring_ring_dontfork);
    _DL_RESOLVE(io_uring_queue_exit);
    _DL_RESOLVE(io_uring_peek_batch_cqe);
    _DL_RESOLVE(io_uring_wait_cqes);
    _DL_RESOLVE(io_uring_wait_cqe_timeout);
    _DL_RESOLVE(io_uring_submit);
    _DL_RESOLVE(io_uring_submit_and_wait);
    _DL_RESOLVE(io_uring_get_sqe);
    _DL_RESOLVE(io_uring_register_buffers);
    _DL_RESOLVE(io_uring_unregister_buffers);
    _DL_RESOLVE(io_uring_register_files);
    _DL_RESOLVE(io_uring_unregister_files);
    _DL_RESOLVE(io_uring_register_files_update);
    _DL_RESOLVE(io_uring_register_eventfd);
    _DL_RESOLVE(io_uring_register_eventfd_async);
    _DL_RESOLVE(io_uring_unregister_eventfd);
    _DL_RESOLVE(io_uring_register_probe);
    _DL_RESOLVE(io_uring_register_personality);
    _DL_RESOLVE(io_uring_unregister_personality);
//    _DL_RESOLVE(io_uring_register_restrictions); FIXME - resolve failed
//    _DL_RESOLVE(io_uring_enable_rings); FIXME - resolve failed - they are not in .so, checked with nm.
    _DL_RESOLVE(__io_uring_sqring_wait);
    _DL_RESOLVE(__io_uring_get_cqe);
    
        // functions that aren't dynamically resolvable as
        // they are defined static inline in liburing.h
        // they are manually stubbed in CNIOLinux.h for platforms without uring
        // so we can call the liburing-header defined one directly below
        // _DL_RESOLVE(io_uring_cqe_seen);
    
    return 0;
}

    // ring setup/teardown
struct io_uring_probe *CNIOLinux_io_uring_get_probe_ring(struct io_uring *ring)
{
    return liburing_functions.io_uring_get_probe_ring(ring);
}

struct io_uring_probe * CNIOLinux_io_uring_get_probe(void)
{
    return liburing_functions.io_uring_get_probe();
}

void CNIOLinux_io_uring_free_probe(struct io_uring_probe *probe)
{
    return liburing_functions.io_uring_free_probe(probe);
}

int CNIOLinux_io_uring_queue_init_params(unsigned entries, struct io_uring *ring,
    struct io_uring_params *p)
{
    return liburing_functions.io_uring_queue_init_params(entries, ring, p);
}

int CNIOLinux_io_uring_queue_init(unsigned entries, struct io_uring *ring,
    unsigned flags)
{
    return liburing_functions.io_uring_queue_init( entries, ring, flags);
}

int CNIOLinux_io_uring_queue_mmap(int fd, struct io_uring_params *p,
    struct io_uring *ring)
{
    return liburing_functions.io_uring_queue_mmap(fd, p, ring);
}

int CNIOLinux_io_uring_ring_dontfork(struct io_uring *ring)
{
    return liburing_functions.io_uring_ring_dontfork(ring);
}

void CNIOLinux_io_uring_queue_exit(struct io_uring *ring)
{
    return liburing_functions.io_uring_queue_exit(ring);
}

unsigned CNIOLinux_io_uring_peek_batch_cqe(struct io_uring *ring,
    struct io_uring_cqe **cqes, unsigned count)
{
    return liburing_functions.io_uring_peek_batch_cqe(ring, cqes, count);
}

int CNIOLinux_io_uring_wait_cqes(struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr, unsigned wait_nr,
    struct __kernel_timespec *ts, sigset_t *sigmask)
{
    return liburing_functions.io_uring_wait_cqes(ring, cqe_ptr, wait_nr, ts, sigmask);
}

int CNIOLinux_io_uring_wait_cqe_timeout(struct io_uring *ring,
    struct io_uring_cqe **cqe_ptr, struct __kernel_timespec *ts)
{
    return liburing_functions.io_uring_wait_cqe_timeout(ring, cqe_ptr, ts);
}

int CNIOLinux_io_uring_submit(struct io_uring *ring)
{
    return liburing_functions.io_uring_submit(ring);
}

int CNIOLinux_io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr)
{
    return liburing_functions.io_uring_submit_and_wait(ring, wait_nr);
}

struct io_uring_sqe *CNIOLinux_io_uring_get_sqe(struct io_uring *ring)
{
    return liburing_functions.io_uring_get_sqe(ring);
}


int CNIOLinux_io_uring_register_buffers(struct io_uring *ring,
                    const struct iovec *iovecs,
                    unsigned nr_iovecs)
{
    return liburing_functions.io_uring_register_buffers(ring, iovecs, nr_iovecs);
}

int CNIOLinux_io_uring_unregister_buffers(struct io_uring *ring)
{
    return liburing_functions.io_uring_unregister_buffers(ring);
}

int CNIOLinux_io_uring_register_files(struct io_uring *ring, const int *files,
                    unsigned nr_files)
{
    return liburing_functions.io_uring_register_files(ring, files, nr_files);
}

int CNIOLinux_io_uring_unregister_files(struct io_uring *ring)
{
    return liburing_functions.io_uring_unregister_files(ring);
}

int CNIOLinux_io_uring_register_files_update(struct io_uring *ring, unsigned off,
                    int *files, unsigned nr_files)
{
    return liburing_functions.io_uring_register_files_update(ring, off, files, nr_files);
}

int CNIOLinux_io_uring_register_eventfd(struct io_uring *ring, int fd)
{
    return liburing_functions.io_uring_register_eventfd(ring, fd);
}

int CNIOLinux_io_uring_register_eventfd_async(struct io_uring *ring, int fd)
{
    return liburing_functions.io_uring_register_eventfd_async(ring, fd);
}

int CNIOLinux_io_uring_unregister_eventfd(struct io_uring *ring)
{
    return liburing_functions.io_uring_unregister_eventfd(ring);
}

int CNIOLinux_io_uring_register_probe(struct io_uring *ring,
                    struct io_uring_probe *p, unsigned nr)
{
    return liburing_functions.io_uring_register_probe(ring, p, nr);
}

int CNIOLinux_io_uring_register_personality(struct io_uring *ring)
{
    return liburing_functions.io_uring_register_personality(ring);
}

int CNIOLinux_io_uring_unregister_personality(struct io_uring *ring, int id)
{
    return liburing_functions.io_uring_unregister_personality(ring, id);
}

int CNIOLinux_io_uring_register_restrictions(struct io_uring *ring,
                      struct io_uring_restriction *res,
                      unsigned int nr_res)
{
    return 0;
  //  return liburing_functions.io_uring_register_restrictions(ring, res, nr_res);
}

int CNIOLinux_io_uring_enable_rings(struct io_uring *ring)
{
    return 0;
//    return liburing_functions.io_uring_enable_rings(ring);
}

inline int CNIOLinux___io_uring_sqring_wait(struct io_uring *ring)
{
    return liburing_functions.__io_uring_sqring_wait(ring);
}

    // mark the CQE as done
    // This function is declared as static inline in the liburing
    // headers so we need to manually stub it in CNILinux.h and
    // ensure that we call the one defined in the liburing header here
    // this function is inlined down to calls to atomic_store_explicit etc
    // so it doesn't reference symbols from liburing and we should be ok.
inline void CNIOLinux_io_uring_cqe_seen(struct io_uring *ring, struct io_uring_cqe *cqe)
{
    io_uring_cqe_seen(ring, cqe);
    return;
}
// duplication of inline code here




/*
 * Return an IO completion, waiting for 'wait_nr' completions if one isn't
 * readily available. Returns 0 with cqe_ptr filled in on success, -errno on
 * failure.
 */
int CNIOLinux_io_uring_wait_cqe_nr(struct io_uring *ring,
                      struct io_uring_cqe **cqe_ptr,
                      unsigned wait_nr)
{
    return liburing_functions.__io_uring_get_cqe(ring, cqe_ptr, 0, wait_nr, NULL);
}

/*
 * Return an IO completion, if one is readily available. Returns 0 with
 * cqe_ptr filled in on success, -errno on failure.
 */
int CNIOLinux_io_uring_peek_cqe(struct io_uring *ring,
                    struct io_uring_cqe **cqe_ptr)
{
    return CNIOLinux_io_uring_wait_cqe_nr(ring, cqe_ptr, 0);
}

/*
 * Return an IO completion, waiting for it if necessary. Returns 0 with
 * cqe_ptr filled in on success, -errno on failure.
 */
int CNIOLinux_io_uring_wait_cqe(struct io_uring *ring,
                    struct io_uring_cqe **cqe_ptr)
{
    return CNIOLinux_io_uring_wait_cqe_nr(ring, cqe_ptr, 1);
}

/*inline extern struct io_uring_sqe *CNIOLinux_io_uring_get_sqe(struct io_uring *ring)
{
    return io_uring_get_sqe(ring);
}

inline void CNIOLinux_io_uring_submit(struct io_uring *ring)
{
    io_uring_submit(ring);
    return;
}
*/

#endif
