#define SYSCALL_DEFINE0(sname)                                  \
        SYSCALL_METADATA(_##sname, 0);                          \
        asmlinkage long sys_##sname(void)

#define __MAP0(m,...)
#define __MAP1(m,t,a) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)


#define __SC_DECL(t, a) t a
#define __TYPE_IS_LL(t) (__same_type((t)0, 0LL) || __same_type((t)0, 0ULL))
#define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a
#define __SC_CAST(t, a) (t) a
#define __SC_ARGS(t, a) a
#define __SC_TEST(t, a) (void)BUILD_BUG_ON_ZERO(!__TYPE_IS_LL(t) && sizeof(t) > sizeof(long))

#define __SC_STR_ADECL(t, a)    #a
#define __SC_STR_TDECL(t, a)    #t

#define SYSCALL_METADATA(sname, nb, ...)                        \
        static const char *types_##sname[] = {                  \
                __MAP(nb,__SC_STR_TDECL,__VA_ARGS__)            \
        };                                                      \
        static const char *args_##sname[] = {                   \
                __MAP(nb,__SC_STR_ADECL,__VA_ARGS__)            \
        };                                                      \
        SYSCALL_TRACE_ENTER_EVENT(sname);                       \
        SYSCALL_TRACE_EXIT_EVENT(sname);                        \
        static struct syscall_metadata __used                   \
          __syscall_meta_##sname = {                            \
                .name           = "sys"#sname,                  \
                .syscall_nr     = -1,   /* Filled in at boot */ \
                .nb_args        = nb,                           \
                .types          = nb ? types_##sname : NULL,    \
                .args           = nb ? args_##sname : NULL,     \
                .enter_event    = &event_enter_##sname,         \
                .exit_event     = &event_exit_##sname,          \
                .enter_fields   = LIST_HEAD_INIT(__syscall_meta_##sname.enter_fields), \
        };                                                      \
        static struct syscall_metadata __used                   \
          __attribute__((section("__syscalls_metadata")))       \
         *__p_syscall_meta_##sname = &__syscall_meta_##sname;

#define PAGE_SIZE 4096
SYSCALL_DEFINE0(getpagesize)
{
        return 4096;
}


#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define SYSCALL_DEFINEx(x, sname, ...)                          \
        SYSCALL_METADATA(sname, x, __VA_ARGS__)                 \
        __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define __PROTECT(...) asmlinkage_protect(__VA_ARGS__)
#define __SYSCALL_DEFINEx(x, name, ...)                                 \
        asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))       \
                __attribute__((alias(__stringify(SyS##name))));         \
        static inline long SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__));  \
        asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__));      \
        asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__))       \
        {                                                               \
                long ret = SYSC##name(__MAP(x,__SC_CAST,__VA_ARGS__));  \
                __MAP(x,__SC_TEST,__VA_ARGS__);                         \
                __PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));       \
                return ret;                                             \
        }                                                               \
        static inline long SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)

SYSCALL_DEFINE2(listen, int, fd, int, backlog)
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
