#include<stdio.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

extern int test_export();

#define LIB_CACULATE_PATH "/data/local/tmp/libshellcode-relocate.so"

int main(){

    printf("loading %s\n", LIB_CACULATE_PATH);
    
    void *handle = NULL;
    handle = dlopen(LIB_CACULATE_PATH, RTLD_NOW);
    //void* (*p_dlopen)(const char*, int) = dlopen;
    //printf("dlopen addr:%p\n", p_dlopen);
    if(handle == NULL){
        printf("dlopen error...\n");
        return -1;
    }

    void (*test_export)() = dlsym(handle, "test_export");
    if(test_export == NULL){
        printf("dlsym error...\n");
        return -1;
    }
    
    
    test_export();

    printf("exit\n");

    return 0;
}