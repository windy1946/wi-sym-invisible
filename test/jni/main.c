#include<stdio.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

// extern int test_export();

#define LIB_CACULATE_PATH "/data/local/tmp/libtest.so"

typedef void* (*p_test)();

int main(){

    printf("[+]loading %s\n", LIB_CACULATE_PATH);
    
    char stop = getchar();

    void *handle = NULL;
    handle = dlopen("/system/lib64/liblog.so", 2);
    if(handle == NULL){
        printf("handle is null\n");
    }else{
        printf("find liblog.so\n");
    }
    void* sym = dlsym(handle, "getchar");
    void* (*p_getchar) = getchar;

    printf("get char addr=====:%p\n", p_getchar);
    if(sym == NULL){
        printf("is null\n");
    }else{
        printf("find\n");
        printf("getchar addr : %p\n", sym);
    }
    
    dlclose(handle);

    handle = dlopen(LIB_CACULATE_PATH, RTLD_NOW);
    //void* (*p_dlopen)(const char*, int) = dlopen;
    //printf("dlopen addr:%p\n", p_dlopen);
    if(handle == NULL){
        printf("dlopen error...\n");
        return -1;
    }
    printf("[+]dlopen ok");
    stop = getchar();

    p_test test_fun = dlsym(handle, "test_export");
    if(test_fun == NULL){
        printf("dlsym error...\n");
        return -1;
    }else{
        printf("dlsym test_export() ok, addr:%p \n", test_fun);
    }

    test_fun();

    printf("dlclose()\n");
    dlclose(handle);

    printf("exit\n");

    return 0;
}