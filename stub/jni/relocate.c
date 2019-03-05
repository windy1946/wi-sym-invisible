#include <stdio.h>
#include <stdbool.h>
#include <elf.h>
#include "log.h"
#include "elf_h.h"

#ifdef M_ARM64  //64bit
    #define log_name  "__android_log_print"
    #define log_path  "/system/lib64/liblog.so"
    #define linker_path  "/system/bin/linker64"
    #define dlopen_name  "__dl_dlopen"
    #define dlsym_name  "__dl_dlsym"
    #define mprotect_name  "mprotect"
    #define libc_path  "/system/lib64/libc.so"
#else //32bit
    #define log_name  "__android_log_print"
    #define log_path  "/system/lib/liblog.so"
    #define linker_path  "/system/bin/linker"
    #define dlopen_name  "__dl_dlopen"
    #define dlsym_name  "__dl_dlsym"
    #define mprotect_name  "mprotect"
    #define libc_path  "/system/lib/libc.so"
#endif

extern void* get_function(const char* lib_path, int lib_len, const char* fun_name, int name_len);

void link_image(Elf_Ehdr* ehdr);
unsigned long wi_strlen(const char* str);

typedef void* (*p_dlopen)(const char*, int);
typedef void* (*p_dlsym)(void*, const char*);
typedef void* (*p_mprotect)(void *addr, size_t len, int prot);
typedef void* (*p_log)(int index, const char* tag, const char* format, ...);

void* get_base_addr(){
    unsigned long base_addr = 0;
    unsigned long offset = 0;

#ifdef M_ARM64
	asm(
        "adr %0, wi_symbol\n"   //define in syscall-arm64.S
        "ldr %1, wi_offset\n"
        "b next0\n"
        "wi_offset: .dword 0xbeefbee1\n"
        "next0:\n"
        :"=r"(base_addr), "=r"(offset)
    );
#elif M_ARM

#elif M_X86

#endif
    return (void*)(base_addr - offset);
}

void on_start(){
    unsigned long offset_to_init_data = NULL;
    
#ifdef M_ARM64
	asm (
        "ldr %0, offset2init\n"
		"b next1\n"
        "offset2init: .dword 0xbeefbee0\n"
		"next1:\n"
		:"=r"(offset_to_init_data)
		:
		);
#elif M_ARM

#elif M_X86

#endif

    void* p_ehdr = NULL;
    
    Elf_Ehdr* ehdr = (Elf_Ehdr*)get_base_addr();

    p_log wi_log= get_function(log_path, wi_strlen(log_path), log_name, wi_strlen(log_name));

    LOGD("linking image...");
    
    link_image(ehdr);

    if(offset_to_init_data != 0){
        void (*orig_init)() = (void*)((uint8_t*)ehdr - offset_to_init_data);
        orig_init();
    }

}   

unsigned long wi_strlen(const char* str){
    unsigned long len = 0;

    for(len=0; *str++ != '\0'; len++);

    return len;
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
   
    p_log wi_log= get_function(log_path, wi_strlen(log_path), log_name, wi_strlen(log_name));

    p_dlopen wi_dlopen = get_function(linker_path, wi_strlen(linker_path), dlopen_name, wi_strlen(dlopen_name));
    
    p_dlsym wi_dlsym = get_function(linker_path, wi_strlen(linker_path), dlsym_name, wi_strlen(dlsym_name));

    int i = 0;
    void* sym_addr = NULL;
    for(i=0; i<needed_count; i++){
        const char* library_name = (const char*)needed_libraries[i];
        LOGD("finding library %s", library_name);

        if(wi_dlopen == NULL){
            LOGD("[+]p_dlopen addr error");
        }
        void* handle = wi_dlopen(library_name, 2);
        if(handle == NULL){
            LOGE("can not find library:%s", library_name);
            return 0;
        }
        LOGD("find library %s", library_name);

        if(wi_dlopen == NULL){
            LOGD("[+]p_dlsym addr error");
        }
        sym_addr = wi_dlsym(handle, sym_name);
        
        if(sym_addr != NULL){
            LOGD("find:[%s] in [%s]", sym_name, library_name);
            break;
        }
    }

    if(sym_addr == NULL){
        LOGE("can not find symbol:%s", sym_name);
        return 0;
    }

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
    
    p_log wi_log = get_function(log_path, wi_strlen(log_path), log_name, wi_strlen(log_name));

    p_mprotect wi_mprotect = get_function(libc_path, wi_strlen(libc_path), mprotect_name, wi_strlen(mprotect_name));

    Elf_Rela* rela = NULL;
    Elf_Addr sym_addr = 0;
    int i = 0;
    
    for(i=0; i<rela_count_; i++){
        rela = &rela_[i];
        //Elf_Xword sym_index = ELF_R_SYM(rela->r_info);
        Elf_Xword sym_index = rela->r_info;
        const char* sym_name = strtab_ + symtab_[sym_index].st_name;
        const Elf_Sym* symbol = NULL;
        unsigned long symbol_bias = 0;

        LOGD("symbol name : %s", sym_name);

        Elf_Addr reloc = (Elf_Addr)rela->r_offset + load_bias;
        
        LOGD("soinfo looking up...");
        sym_addr = m_soinfo_do_lookup(sym_name, strtab_, needed_libraries, needed_count);

        LOGD("relocating got:%p, new addr:%p", reloc, sym_addr);
        if(sym_addr != 0 && sym_addr-*(Elf_Addr*)reloc !=0 ){
            //PROT_WRITE 2
            //PROT_READ 1
            LOGD("mprotect addr : %p", reloc-reloc%0x1000);
            wi_mprotect((void*)(reloc-reloc%0x1000), 0x1000, 2 | 1);
            *(Elf_Addr*)reloc = (Elf_Addr)sym_addr;
            wi_mprotect((void*)(reloc-reloc%0x1000), 0x1000, 1);
            LOGD("relocating ok");
        }
    }

    return true;
}


void link_image(Elf_Ehdr* ehdr){
    
    p_log wi_log= get_function(log_path, wi_strlen(log_path), log_name, wi_strlen(log_name));

    Elf_Phdr* phdr = (Elf_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff);
    size_t phnum = ehdr->e_phnum;
    unsigned long load_bias = (unsigned long)ehdr;
    Elf_Dyn* dynamic = NULL;
    Elf_Word dynamic_flags = 0;
    LOGD("load_bias : %lx", load_bias);
    phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);
    
    const char* strtab_;
    Elf_Dyn* dyn = NULL;
    uint32_t needed_count = 0;
    unsigned long needed_libraries[20];

    for(dyn = dynamic; dyn->d_tag != DT_NULL; dyn++){
        switch(dyn->d_tag){
            case DT_STRTAB:
                //LOGD("strtab...");
                strtab_ = (const char*)(load_bias + (Elf_Addr)dyn->d_un.d_ptr);  // + load_bias   ???
                break;
            case DT_NEEDED:
                if(needed_count >= 20){
                    LOGE("there are too many libraries");
                    return;
                }
                needed_libraries[needed_count] = (Elf_Word)dyn->d_un.d_val;
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

    void* relo_data = NULL;
    void* dynsym_data = NULL;
    void* strtab_data = NULL;
#ifdef M_ARM64
	asm (
        "adr %0, relodata\n"
        "adr %1, dynsymdata\n"
        "adr %2, strtabdata\n"
		"b next\n"
        "relodata: .dword 0xbeefbee2\n"
        ".space 0x100\n"
        "dynsymdata: .dword 0xbeefbee3\n"
        ".space 0x100\n"
        "strtabdata: .dword 0xbeefbee4\n"
        ".space 0x100\n"
		"next:\n"
		:"=r"(relo_data), "=r"(dynsym_data), "=r"(strtab_data)
		:
		);
#elif M_ARM

#elif M_X86

#endif
    
    relocate(load_bias, (Elf_Rela*)relo_data, 1, (Elf_Sym*)dynsym_data, (const char*)strtab_data, needed_libraries, needed_count);
    
}



