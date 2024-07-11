//gcc Catcat.c -z now -o Catcat
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
struct mycats
{
     char name[20];
     int color;
};
char cat_type[]="          # # # # # # # # # # # # # #\n         #                           #~~~~~~~~~~~~~~~~~~~~\n    ##   #       ##                  #\n    #  # #     #  #                  #~~~~~~~~~~~~~~~~~~~~\n    #   # # # #   #                  #       # #\n   #               #                 # # # #    #~~~~~~~~~\n #     #      #      #               #        #\n #                   #               # # # # #~~~~~~~~~~~~\n   #    |__|__|    #                 #\n     # # # # # # # # # # # # # # # #  ~~~~~~~~~~~~~~~~~~~~\n      # #     # #       # #     # #";

int init_func(){
     setvbuf(stdin,0,2,0);
     setvbuf(stdout,0,2,0);
     setvbuf(stderr,0,2,0);
     return 0;
}
int getnum(){
     char buf[20];
     read(0,buf,0x10);
     return atoi(buf);
}
int menu(){
     puts("\033[0m1.Add cats");
     puts("2.Change the cat");
     puts("3.Show your cat");
     puts("4.exit");
     printf(">>");
     return getnum();
}
int choose_color(){
     puts("1.back");
     puts("2.bule");
     puts("3.green");
     puts("4.cyan");
     puts("5.red");
     puts("6.purple");
     puts("7.yellow");
     puts("8.white");
     printf(">>");
     return getnum();    
}
void show_color(int my_color){
     switch(my_color){
          case 1:
              printf("\033[0;30m %s\n",cat_type);
              break;
          case 2:
              printf("\033[0;34m %s\n",cat_type);
              break;
          case 3:
              printf("\033[0;32m %s\n",cat_type);
              break;
          case 4:
              printf("\033[0;36m %s\n",cat_type);
              break;
          case 5:
              printf("\033[0;31m %s\n",cat_type);
              break;
          case 6:
              printf("\033[0;35m %s\n",cat_type);
              break;
          case 7:
              printf("\033[0;33m %s\n",cat_type);
              break;
          case 8:
              printf("\033[0;37m %s\n",cat_type);
              break;
          default:
             break;
     }
}
int main(){
     int temp;
     int index;
     int num=0;
     bool judge=false;
     struct mycats cats[4];
     char newname[20]; 
     char mychoice[20];
     char cat_index[20];
     init_func();
     while(true){
          index=menu();
          switch(index){
               case 1:
                  if(num>3){
                    puts("you have too many cats!!");
                    judge=true;
                    break;
                  }
                  puts("now you have a cat");
                  puts("plz give the cat a name:");
                  read(0,cats[num].name,0x10);
                  puts("Please choose a color for your cat");
                  temp=choose_color();
                  if(temp>=1&&temp<=8){
                      cats[num].color=temp;
                      num++;
                      puts("Okk,you have a cute cat!");
                  }else{
                   puts("Invalid input");
                  }
                  break;
               case 2:
                  puts("Which cat's name do you want to change");
                  puts("please input index");
                  read(0,cat_index,0xC);
                  if(atoi(cat_index)>=0&&atoi(cat_index)<=3){
                  }
                  else{
                    puts("Invalid input");
                    break;
                  }
                  puts("Do you want to change  the cats name(yes/no)?");
                  read(0,mychoice,0x30);
                  if(strncmp(mychoice,"YES",3)==0||strncmp(mychoice,"yes",3)==0){
                     puts("plz input the cat's new name:");
                     read(0,newname,0xC);
                     memcpy(cats[atoi(cat_index)].name,newname,0xc);
                     puts("Change success!!");
                  }
                  break;
               case 3:
                  for(int i=0;i<num;i++){
                    printf("cat%d name is:",i);
                    printf(cats[i].name);
                    show_color(cats[i].color);
                  }
                  break;
               case 4:
                  puts("bye~~~~");
                  _exit(0);
               default:
                  puts("Invalid input");
                  break;
          }
          if(judge==true){
               break;
          }         
     }
}
       
