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
