#include <stdio.h>
#include <stdbool.h>
#include <elf.h>
#include "log.h"
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
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "elf_h.h"

#define STT_GNU_IFUNC 10

extern void* get_function(const char* lib_path, int lib_len, const char* fun_name, int name_len);

void link_image(Elf_Ehdr* ehdr);
static char relo_data[100]={'m','a','g','i','c','b','e','a','a'};
static char dynsym_data[100]={'m','a','g','i','c','b','e','a','b'};
static char strtab_data[100]={'m','a','g','i','c','b','e','a','c'};
void* (*p_dlopen)(const char*, int) = NULL;
void* (*p_dlsym)(void*, const char*) = NULL;
void* (*p_mprotect)(void *addr, size_t len, int prot) = NULL;

__volatile__ static char offset_data[4]={0xbe, 0xef, 0xbe, 0xef};


void read_elf(){
    void* p_ehdr = NULL;
    unsigned long address_off = *(unsigned long*)(offset_data);
    
    void* (*p_read_elf) = (void*)read_elf;

    Elf_Ehdr* ehdr = (Elf_Ehdr*)((unsigned char*)p_read_elf - address_off);

    const char* linker64_path = "/system/bin/linker64";
    const char* dlopen_name = "__dl_dlopen";    
    p_dlopen = get_function(linker64_path, strlen(linker64_path), dlopen_name, strlen(dlopen_name));

    const char* dlsym_name = "__dl_dlsym";
    p_dlsym = get_function(linker64_path, strlen(linker64_path), dlsym_name, strlen(dlsym_name));

    const char* mprotect_name = "mprotect";
    const char* libc_path = "/system/bin/libc.so";
    p_mprotect = get_function(libc_path, strlen(libc_path), mprotect_name, strlen(mprotect_name));

    LOGD("p_dlopen addr :%p, dlopen addr :%p", p_dlopen, dlopen);
    LOGD("p_dlsym addr :%p, dlsym addr :%p", p_dlsym, dlsym);
    LOGD("p_mprotect addr :%p, mprotect addr :%p", p_mprotect, mprotect);
   
    LOGD("linking image...");
    link_image(ehdr);

}   

int test_export(){
    
    read_elf();

    char ch = getchar();

    printf("getchar : %c\n", ch);

    return 0;
}

void phdr_table_get_dynamic_section(Elf_Phdr* phdr_table, size_t phdr_count,
                                    unsigned long load_bias, Elf_Dyn** dynamic,
                                    Elf_Word* dynamic_flags) {
    *dynamic = NULL;
    size_t i = 0;
    for (i = 0; i<phdr_count; ++i) {
        const Elf_Phdr* phdr = (Elf_Phdr*)&phdr_table[i];
        if (phdr->p_type == PT_DYNAMIC) {
            *dynamic = (Elf_Dyn*)(load_bias + phdr->p_vaddr);
            if (dynamic_flags) {
                *dynamic_flags = phdr->p_flags;
            }
            return;
        }
    }
}

Elf_Addr m_soinfo_do_lookup(const char* sym_name, const char* strtab_, unsigned long needed_libraries[], uint32_t needed_count){
    int i = 0;
    void* sym_addr = NULL;
    for(i=0; i<needed_count; i++){
        const char* library_name = (const char*)needed_libraries[i];
        LOGD("finding library %s", library_name);

        if(p_dlopen == NULL){
            LOGD("[+]p_dlopen addr error");
        }
        void* handle = p_dlopen(library_name, 1);
        if(handle == NULL){
            LOGE("can not find library:%s", library_name);
            return 0;
        }
        LOGD("find library %s", library_name);

        if(p_dlopen == NULL){
            LOGD("[+]p_dlsym addr error");
        }
        sym_addr = p_dlsym(handle, sym_name);
        
        if(sym_addr != NULL){
            //LOGD("find:[%s] in [%s]", sym_name, library_name);
            break;
        }
    }

    if(sym_addr == NULL){
        LOGE("can not find symbol:%s", sym_name);
        return 0;
    }
    //LOGD("[%s] addr:%p\n", sym_name, sym_addr);
    return (Elf_Addr)sym_addr;
}

//#define ELF_R_SYM(info)   (((info) >> 0) & 0xffffffff)
//#define ELF_R_TYPE(info)  (((info) >> 56) & 0xff)
Elf_Addr call_ifunc_resolver(Elf_Addr resolver_addr) {
  typedef Elf_Addr (*ifunc_resolver_t)(void);
  ifunc_resolver_t ifunc_resolver = *(ifunc_resolver_t*)(resolver_addr);
  Elf_Addr ifunc_addr = ifunc_resolver();
  return ifunc_addr;
}


bool relocate(unsigned long load_bias, Elf_Rela* rela_, Elf_Word rela_count_, 
Elf_Sym* symtab_, 
const char* strtab_,
unsigned long needed_libraries[], uint32_t needed_count)
{
    Elf_Rela* rela = NULL;
    Elf_Addr sym_addr = 0;
    int i = 0;
    for(i=0; i<rela_count_; i++){
        rela = &rela_[i];
        Elf_Xword sym_index = ELF_R_SYM(rela->r_info);
        
        const char* sym_name = strtab_ + symtab_[sym_index].st_name;
        const Elf_Sym* symbol = NULL;
        unsigned long symbol_bias = 0;

        LOGD("symbol name : %s", sym_name);

        Elf_Addr reloc = (Elf_Addr)rela->r_offset + load_bias;
        
        LOGD("soinfo looking up...");
        sym_addr = m_soinfo_do_lookup(sym_name, strtab_, needed_libraries, needed_count);

        LOGD("relocating...");
        if(sym_addr != 0 && sym_addr-*(Elf_Addr*)reloc !=0 ){
            //PROT_WRITE 2
            //PROT_READ 1
            mprotect((void*)(reloc-reloc%0x1000), 0x1000, 2 | 1);
            *(Elf_Addr*)reloc = (Elf_Addr)sym_addr;
            mprotect((void*)(reloc-reloc%0x1000), 0x1000, 1);
            LOGD("relocating ok");
        }
    }

    return true;
}


void link_image(Elf_Ehdr* ehdr){
    Elf_Phdr* phdr = (Elf_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff);
    size_t phnum = ehdr->e_phnum;
    unsigned long load_bias = (unsigned long)ehdr;
    Elf_Dyn* dynamic = NULL;
    Elf_Word dynamic_flags = 0;
    LOGD("load_bias : %lx", load_bias);
    phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);
    size_t rela_count_ = 0;
    size_t plt_rela_count_ = 0;
    Elf_Rela* rela_ = NULL;
    Elf_Rela* plt_rela_ = NULL;
    Elf_Sym* symtab_ = NULL;
    const char* strtab_;
    Elf_Dyn* dyn = NULL;
    uint32_t needed_count = 0;
    unsigned long needed_libraries[20];

    for(dyn = dynamic; dyn->d_tag != DT_NULL; dyn++){
        switch(dyn->d_tag){
            case DT_RELA:
                rela_ = (Elf_Rela*)(load_bias + (dyn->d_un.d_ptr));  // + load_bias  ????
                break; 
            case DT_RELASZ:
                //LOGD("relasz...");
                rela_count_ =  (Elf_Word)dyn->d_un.d_val / sizeof(Elf_Rela);
                //LOGD("relasz : %ld", rel_count_);
                break;
            case DT_SYMTAB:
                //LOGD("symtab...");
                symtab_ = (Elf_Sym*)(load_bias + (Elf_Addr)(dyn->d_un.d_ptr));  // + load_bias   ???
                break;
            case DT_STRTAB:
                //LOGD("strtab...");
                strtab_ = (const char*)(load_bias + (Elf_Addr)dyn->d_un.d_ptr);  // + load_bias   ???
                break;
            case DT_JMPREL:
                plt_rela_ = (Elf_Rela*)(load_bias + (Elf_Addr)dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                plt_rela_count_ = (Elf_Word)dyn->d_un.d_val / sizeof(Elf_Rela);
                break;
            case DT_NEEDED:
                if(needed_count >= 20){
                    LOGE("there are too many libraries");
                    return;
                }
                needed_libraries[needed_count] = (Elf_Word)dyn->d_un.d_val;
                //LOGD("d_val : %lx", needed_libraries[needed_count]);
                needed_count++;
                break;
            default:
                break;
        }
    }
    int i = 0;
    for(i = 0; i < needed_count; i++){
        needed_libraries[i] = (unsigned long)(needed_libraries[i] + strtab_);

    }
    relocate(load_bias, (Elf_Rela*)relo_data, 1, (Elf_Sym*)dynsym_data, (const char*)strtab_data, needed_libraries, needed_count);
    
}



