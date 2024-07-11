//gcc -no-pie S0rw.c -fno-stack-protector -z now -o S0rw  -lseccomp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <seccomp.h>
#include <linux/seccomp.h>

char buf[0x30]="Ple4se use the srop attack to hack the program!\n";
int seccomp(){
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_load(ctx);
    return 0;
}
int main(){
     char backdoor[0x10];
     seccomp();
     syscall(1,1,buf,0x30);
     return syscall(0,0,backdoor,0x300);
}
int vuln(){
    return 15;
}
