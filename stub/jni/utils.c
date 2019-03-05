#include <string.h>
//#include <asm-generic/unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include "elf_h.h"

#define PAGE_SIZE   4096

#define LOGD 
#define LOGE

inline
int _memcmp(const void* s1, const void* s2,size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;
    while(n--)
        if( *p1 != *p2 )
            return *p1 - *p2;
        else
            p1++,p2++;
    return 0;
}


extern long _syscall(int n,...);

void* get_function(const char* lib_path, int lib_len, const char* fun_name, int name_len){
    unsigned char maps_str[] = {
        0x2F, 0x70, 0x72, 0x6F, 0x63, 0x2F, 0x73, 0x65,
        0x6C, 0x66, 0x2F, 0x6D, 0x61, 0x70, 0x73, 0x00
    };// /proc/self/maps  
    
    int fd = 0;
#ifdef M_ARM64
    fd = _syscall(__NR_openat, 0, maps_str, O_RDONLY);
#elif M_ARM
    fd = _syscall(__NR_open, 0, maps_str, O_RDONLY);
#elif M_X86
    fd = _syscall(__NR_open, 0, maps_str, O_RDONLY);
# endif
//------------------------
    
    if (fd < 0) {
        LOGD("open maps fail");
        return 0;   //open fail
    }
    
    char *line_hdr = NULL;
    
    int readsize = 0;
    char readch;
    int maxline = 200;
    char eachline[maxline];
    int index = 0;
    while((readsize=_syscall(__NR_read, fd, &readch, 1))>0){
        eachline[index++] = readch;
        if(index >= maxline){
            index = 0;
        }
        if(readch=='\n' || readch==EOF){
            eachline[index] = '\0';
            if(index <= 21){
                index = 0;
                continue;
            }
            int i = 0;
            for(i = 0; i<index; i++){
                if(_memcmp(eachline+i, lib_path, lib_len) == 0){
                    line_hdr = eachline;
                    break;
                }
            }
            if(line_hdr != NULL){
                break;
            }
            index = 0;
        }
    }  
    
    if (line_hdr == NULL) {
        LOGD("can not find:%s", lib_path);
        _syscall(__NR_close, fd);  //can not find lib
        return 0;
    }
    //parse base address
    char hex[32];
    int i = 0;
    for (i = 0; i<sizeof(hex)/sizeof(hex[0]); i++)
        hex[i] = 0;
    for (i = 0; line_hdr[i] != '-'&& i < sizeof(hex)/sizeof(hex[0]); i++) {
        hex[i] = line_hdr[i];
    }
    
    uint_t libc_baddr = 0;
    unsigned long place = 1;
    int j = 0;
    for (j = i-1; j >= 0; j--) {
        if (hex[j] >= '0' && hex[j] <= '9') {
            libc_baddr += (hex[j] - '0') * place;
        } else if (hex[j] >= 'a' && hex[j] <= 'f') {
            libc_baddr += (hex[j] - 'a' + 10 ) * place;

        }
        place *= 0x10;
    }
    _syscall(__NR_close, fd);

#ifdef M_ARM64
    fd = _syscall(__NR_openat, 0, lib_path, O_RDONLY);
#elif M_ARM
    fd = _syscall(__NR_open, 0, lib_path, O_RDONLY);
#elif M_X86
    fd = _syscall(__NR_open, 0, lib_path, O_RDONLY);
# endif
    //fd = _syscall(__NR_openat, 0 , lib_path, O_RDONLY);
    
    if (fd < 0 ) return NULL;
    
    long len = _syscall(__NR_lseek, fd, 0, SEEK_END);

    _syscall(__NR_lseek, fd, 0, SEEK_SET);

    void* buffer = NULL;
#ifdef M_ARM64
    buffer = (void*)_syscall(__NR_mmap, NULL,
                        (size_t)len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_ANON ,//| MAP_GROWSDOWN ,
                        -1,
                        0);
#elif M_ARM
    buffer = (void*)_syscall(__NR_mmap2, NULL,
                        (size_t)len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_ANON ,//| MAP_GROWSDOWN ,
                        -1,
                        0);
#elif M_X86
    buffer = (void*)_syscall(__NR_mmap2, NULL,
                        (size_t)len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_ANON ,//| MAP_GROWSDOWN ,
                        -1,
                        0);
# endif
/*
    void *buffer = (void*)_syscall(__NR_mmap, NULL,
                        (size_t)len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_ANON ,//| MAP_GROWSDOWN ,
                        -1,
                        0);
*/

    if (buffer == NULL) {
        _syscall(__NR_close, fd);
        return NULL;
    }
    
    long readBytes = _syscall(__NR_read, fd, buffer, len);
    

    if (readBytes != len) {
        //LOGE("read libc so failed!\n");
        _syscall(__NR_close, fd);
        return NULL;
    }

    _syscall(__NR_close, fd);
    
    

#ifdef M_ARM64
    fd = _syscall(__NR_openat, 0, lib_path, O_RDONLY);
#elif M_ARM
    fd = _syscall(__NR_open, 0, lib_path, O_RDONLY);
#elif M_X86
    fd = _syscall(__NR_open, 0, lib_path, O_RDONLY);
# endif
    
    //fd = _syscall(__NR_openat, 0, lib_path, O_RDONLY);


    uint_t addr = 0;
    
    Elf_Ehdr *elfHeader = (Elf_Ehdr *)buffer;
    Elf_Shdr *elfShdr = (Elf_Shdr*)((unsigned char *)elfHeader + elfHeader->e_shoff);
    //LOGE("elfHeader->e_shoff = %x, elfShdr = %x\n", elfHeader->e_shoff, elfShdr);

    //find section name table
    Elf_Shdr *elfSecNameHdr = &elfShdr[elfHeader->e_shstrndx];
    //LOGE("e_shstrndx = %d\n", elfHeader->e_shstrndx);
    
    Elf_Sym *dynsym_addr = NULL;
    int dynsym_num = 0;
    Elf_Off dynstr_offset = 0;
    int find_dyn = 0;
    unsigned char dynsym_str[] = {
        0x2E, 0x64, 0x79, 0x6E, 0x73, 0x79, 0x6D, 0x00
    };//.dynsym
    unsigned char dynstr_str[] = {
        0x2E, 0x64, 0x79, 0x6E, 0x73, 0x74, 0x72, 0x00
    };//.dynstr

    Elf_Sym *symtab_addr = NULL;
    int symtab_num = 0;
    Elf_Off symtab_offset = 0;
    int find_sym = 0;
    unsigned char symtab_str[] = {
        0x2E, 0x73, 0x79, 0x6D, 0x74, 0x61, 0x62, 0x00
    }; //.symtab
    unsigned char strtab_str[] = {
        0x2E, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00
    }; //.strtab
    for (i = 0; i < elfHeader->e_shnum; i++) {
        char *secName = (char *)elfHeader +  elfSecNameHdr->sh_offset + elfShdr[i].sh_name;
        //LOGE("secName = %x\n", elfShdr[i].sh_name);
        //LOGE("sec name = %s\n", secName);
        if (_memcmp(secName, dynsym_str, 7) == 0 && elfShdr[i].sh_type == SHT_DYNSYM) {
            dynsym_addr = (Elf_Sym *)((unsigned long)elfHeader + elfShdr[i].sh_offset);
            dynsym_num = elfShdr[i].sh_size / sizeof(Elf_Sym);
            find_dyn += 1;
        }
        if (_memcmp(secName, dynstr_str, 7) == 0 && elfShdr[i].sh_type == SHT_STRTAB) {
            dynstr_offset = elfShdr[i].sh_offset;
            find_dyn += 1;
        }

        if (_memcmp(secName, symtab_str, 7) == 0 && elfShdr[i].sh_type == SHT_SYMTAB) {
            symtab_addr = (Elf_Sym *)((unsigned long)elfHeader + elfShdr[i].sh_offset);
            symtab_num = elfShdr[i].sh_size / sizeof(Elf_Sym);
            find_sym += 1;
        }

        if (_memcmp(secName, strtab_str, 7) == 0 && elfShdr[i].sh_type == SHT_STRTAB) {
            symtab_offset = elfShdr[i].sh_offset;
            find_sym += 1;
        }

        if (find_dyn == 2 && find_sym == 2)  break;
    }

    uint_t fun_addr = 0;

    if (find_dyn ==2) {
        for (i = 0; i < dynsym_num; i++) {
            char *funcName = (char *)elfHeader + dynstr_offset + dynsym_addr[i].st_name;
            //LOGD("fun_name:%s", funcName);
            if (_memcmp(funcName, fun_name, name_len) == 0) {
                fun_addr = dynsym_addr[i].st_value;
                //LOGE("func name = %s, addr = %llX\n", funcName, fun_addr);
                break;
            }
        }
    }
    if(fun_addr == 0 && find_sym == 2){
        for (i = 0; i < symtab_num; i++) {
            char *funcName = (char *)elfHeader + symtab_offset + symtab_addr[i].st_name;
            //LOGD("fun_name:%s", funcName);
            if (_memcmp(funcName, fun_name, name_len) == 0) {
                fun_addr = symtab_addr[i].st_value;
                //LOGE("func name = %s, addr = %llX\n", funcName, fun_addr);
                break;
            }
        }
    }


    _syscall(__NR_munmap, buffer, len);

    //LOGD("[%s] libc_baddr:%p, fun_addr:%p", fun_name, libc_baddr, fun_addr);

    if(fun_addr == 0){
        LOGE("can not find fun: %s", fun_name);
        return 0;
    }
    
    return (void*)(libc_baddr + fun_addr);
}