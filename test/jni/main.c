#include<stdio.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

// extern int test_export();

#define LIB_PATH "/data/local/tmp/libtest.so"
#define TEST_FUN "test_export"

typedef void* (*p_test)();

int main(){

    printf("[+]begining to dlopen %s\n", LIB_PATH);
    printf("[+]press any key to continue...");
    char stop = getchar();

    void *handle = NULL;

    handle = dlopen(LIB_PATH, RTLD_NOW);
    if(handle == NULL){
        printf("dlopen error...\n");
        return -1;
    }
    printf("[+]dlopen %s ok\n", LIB_PATH);

    printf("[+]begining to dlsym %s\n", TEST_FUN);
    printf("[+]press any key to continue...");

    p_test test_fun = dlsym(handle, TEST_FUN);
    if(test_fun == NULL){
        printf("dlsym error...\n");
        return -1;
    }
    
    printf("[+]dlsym %s ok\n", TEST_FUN);

    printf("[+]running %s\n", TEST_FUN);
    test_fun();
    printf("[+]finish %s\n", TEST_FUN);

    dlclose(handle);

    printf("exit\n");

    return 0;
}