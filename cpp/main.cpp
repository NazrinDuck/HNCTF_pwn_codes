// g++ -o main main.cpp

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

#define CMD_MINING                  1
#define CMD_SHOW_MINERAL_BOOK       2
#define CMD_EDIT_MINERAL_BOOK       3
#define CMD_EXIT                    4

#define MAX_DESCRIPTION_SIZE 0x10

typedef void (*DESC_FUNC)(void);

/* Initialization */

void backdoor()
{
    system("/bin/sh");
}

void alarm_handler(int trash)
{
    std::cout << "TIMEOUT" << std::endl;
    exit(1);
}

void __attribute__((constructor)) initialize(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

/* Print functions */

void print_banner()
{
    std::cout << "Treasure hunt!" << std::endl;
}

void print_menu()
{
    std::cout << std::endl << "[Menu]" << std::endl;
    std::cout << "1. Hunting" << std::endl;
    std::cout << "2. Show" << std::endl;
    std::cout << "3. Edit" << std::endl;
    std::cout << "4. Exit" << std::endl;
}

void print_Money_description()
{
    std::cout << "Name        : Money" << std::endl;
    std::cout << "Symbol      : Mo" << std::endl;
    std::cout << "Description : It can be used to buy things" << std::endl;
}

void print_Gemstone_description()
{
    std::cout << "Name        : Gemstone" << std::endl;
    std::cout << "Symbol      : Ge" << std::endl;
    std::cout << "Description : It refers to the stone or mineral that can meet the requirements of jewelry after being polished and polished" << std::endl;
}

void print_landasikaass_description()
{
    std::cout << "Name        : LandasikaAss" << std::endl;
    std::cout << "Symbol      : La" << std::endl;
    std::cout << "Description : Big Ass" << std::endl;
}

void print_Sock_description()
{
    std::cout << "Name        : Crazyman's Socks" << std::endl;
    std::cout << "Symbol      : Crz" << std::endl;
    std::cout << "Description : Something interesting" << std::endl;
}

void print_CVEcertificate_description()
{
    std::cout << "Name        : CVEcertificate" << std::endl;
    std::cout << "Symbol      : CVE" << std::endl;
    std::cout << "Description : If you have a CVE certificate, you are a big hacker" << std::endl;
}

std::vector<DESC_FUNC> babyfuncs = {
    print_Money_description,
    print_Gemstone_description,
    print_landasikaass_description,
    print_Sock_description,
    print_CVEcertificate_description
};

/* Utils */

int get_int(const char* prompt = ">> ")
{
    std::cout << prompt;

    int x;
    std::cin >> x;
    return x;
}

std::string get_string(const char* prompt = ">> ")
{
    std::cout << prompt;

    std::string x;
    std::cin >> x;
    return x;
}

int get_rand_int(int start, int end)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(start, end);

    return dis(gen);
}

/* Classes */

class treasure
{
public:
    virtual void print_description() const = 0;
};

class UndiscoveredTreasure : public treasure
{
public:
    UndiscoveredTreasure(std::string description_)
    {
        strncpy(description, description_.c_str(), MAX_DESCRIPTION_SIZE);
    }

    void print_description() const override 
    {
        std::cout << "Name        : Unknown" << std::endl;
        std::cout << "Symbol      : Unknown" << std::endl;
        std::cout << "Description : " << description << std::endl;
    }

    char description[MAX_DESCRIPTION_SIZE];
};

class RareTreasure : public treasure
{
public:
    RareTreasure(DESC_FUNC description_)
    : description(description_)
    {

    }

    void print_description() const override 
    {
        if ( description )
            description();
    }

    DESC_FUNC description;   
};


std::vector<treasure *> Treasure;

void hunting()
{
    std::cout << "[+] Hunting..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(get_rand_int(100, 1000)));

    if ( get_rand_int(1, 100) <= 50 )
    {
        std::cout << "You found an undiscovered treasure" << std::endl;
        
        std::string description = get_string("Please Input description : ");
        Treasure.push_back(new UndiscoveredTreasure(description));
    }

    else if ( get_rand_int(1, 100) <= 5 )
    {
        std::cout << "You found a rare treasure" << std::endl;
        
        DESC_FUNC description = babyfuncs[get_rand_int(0, babyfuncs.size() - 1)];
        Treasure.push_back(new RareTreasure(description));
        Treasure.back()->print_description();
    }

    else {
        std::cout << "Found nothing" << std::endl;
    }
        
    return;
}

void edit_treasure_book()
{
    int index = get_int("Index : ");

    if ( index < 0 || index >= Treasure.size() )
    {
        std::cout << "Invalid index" << std::endl;
        return;
    }

    std::string description = get_string("Please Input description : ");
    strncpy(
        static_cast<UndiscoveredTreasure*>(Treasure[index])->description,
        description.c_str(),
        MAX_DESCRIPTION_SIZE
    );
}

void show_treasure_book()
{
    for ( int index = 0; index < Treasure.size(); index++ )
    {
        std::cout << "Idx       : " << index << std::endl;
        Treasure[index]->print_description();
    }

    std::cout << std::endl;
}

/* Main function */

int main(){
    print_banner();

    while(1){
        print_menu();

        int selector = get_int();

        switch (selector){
            case CMD_MINING:
                hunting();
                break;

            case CMD_SHOW_MINERAL_BOOK:
                show_treasure_book();
                break;

            case CMD_EDIT_MINERAL_BOOK:
                edit_treasure_book();
                break;

            case CMD_EXIT:
                return 0;

            default:
                std::cout << "W" << std::endl;
                break;
        }
    }
    return 0;    
}