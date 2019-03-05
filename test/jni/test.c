#include <stdio.h>


int test_export(){
    
    printf("[+]please input a value:");

    char ch = getchar();

    printf("[+]the character you input is : %c\n", ch);

    printf("[+]exit\n");

    return 0;
}


__volatile__ __aligned(0x1000) stub(){
    asm ("\t.space 0x10000\n");
};
