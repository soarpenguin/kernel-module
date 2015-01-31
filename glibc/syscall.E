# 1 "syscall.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 170 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "syscall.c" 2
# 50 "syscall.c"
#
static const char *types__getpagesize[] = { };
static const char *args__getpagesize[] = { };
SYSCALL_TRACE_ENTER_EVENT(_getpagesize);
SYSCALL_TRACE_EXIT_EVENT(_getpagesize);

static struct syscall_metadata __used __syscall_meta__getpagesize = {
    .name = "sys""_getpagesize",
    .syscall_nr = -1,
    .nb_args = 0,
    .types = 0 ? types__getpagesize : NULL,
    .args = 0 ? args__getpagesize : NULL,
    .enter_event = &event_enter__getpagesize,
    .exit_event = &event_exit__getpagesize,
    .enter_fields = LIST_HEAD_INIT(__syscall_meta__getpagesize.enter_fields),
};

static struct syscall_metadata __used
    __attribute__((section("__syscalls_metadata")))
    *__p_syscall_meta__getpagesize = &__syscall_meta__getpagesize;;

asmlinkage long sys_getpagesize(void)
{
        return 4096;
}


static const char *types__listen[] = { "int", "int" };
static const char *args__listen[] = { "fd", "backlog" };
SYSCALL_TRACE_ENTER_EVENT(_listen);
SYSCALL_TRACE_EXIT_EVENT(_listen);

static struct syscall_metadata __used __syscall_meta__listen = {
    .name = "sys""_listen",
    .syscall_nr = -1,
    .nb_args = 2,
    .types = 2 ? types__listen : NULL,
    .args = 2 ? args__listen : NULL,
    .enter_event = &event_enter__listen,
    .exit_event = &event_exit__listen,
    .enter_fields = LIST_HEAD_INIT(__syscall_meta__listen.enter_fields),
};

static struct syscall_metadata __used
    __attribute__((section("__syscalls_metadata")))
    *__p_syscall_meta__listen = &__syscall_meta__listen;

// asmlinkage long sys_listen(int fd, int backlog) __attribute__((alias(__stringify(SyS_listen))));
asmlinkage long sys_listen(int fd, int backlog) __attribute__((alias("SyS_listen")));

static inline long SYSC_listen(int fd, int backlog);
asmlinkage long SyS_listen(__typeof(__builtin_choose_expr((__same_type((int)0, 0LL) || __same_type((int)0, 0ULL)), 0LL, 0L)) fd,
    __typeof(__builtin_choose_expr((__same_type((int)0, 0LL) || __same_type((int)0, 0ULL)), 0LL, 0L)) backlog);

asmlinkage long SyS_listen(__typeof(__builtin_choose_expr((__same_type((int)0, 0LL) || __same_type((int)0, 0ULL)), 0LL, 0L)) fd,
    __typeof(__builtin_choose_expr((__same_type((int)0, 0LL) || __same_type((int)0, 0ULL)), 0LL, 0L)) backlog)
{
    long ret = SYSC_listen((int) fd, (int) backlog);

    (void)BUILD_BUG_ON_ZERO(!(__same_type((int)0, 0LL) || __same_type((int)0, 0ULL)) && sizeof(int) > sizeof(long)),
    (void)BUILD_BUG_ON_ZERO(!(__same_type((int)0, 0LL) || __same_type((int)0, 0ULL)) && sizeof(int) > sizeof(long));

    asmlinkage_protect(2, ret,fd, backlog);
    return ret;
}

static inline long SYSC_listen(int fd, int backlog)
{
        struct socket *sock;
        int err, fput_needed;
        int somaxconn;

        sock = sockfd_lookup_light(fd, &err, &fput_needed);
        if (sock) {
                somaxconn = sock_net(sock->sk)->core.sysctl_somaxconn;
                if ((unsigned int)backlog > somaxconn)
                        backlog = somaxconn;

                err = security_socket_listen(sock, backlog);
                if (!err)
                        err = sock->ops->listen(sock, backlog);

                fput_light(sock->file, fput_needed);
        }
        return err;
}

