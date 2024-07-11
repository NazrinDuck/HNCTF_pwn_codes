// gcc -no-pie fmtstr_level2.c  -z norelro -o fmtstr_level2
#include <stdio.h>
#include <stdlib.h>
int main(){
    char buf[0x120];
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    puts("Welcome to the game of formatting strings");
    puts("Be careful, you only get one shot at this game");
    puts("First please tell me your game ID");
    read(0,buf,0x100);
    printf(buf);
    puts("Okk,try to hack it;sh");
    return 0;
}
