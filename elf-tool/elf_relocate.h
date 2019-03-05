#ifndef H_ELF_RELOCATE
#define H_ELF_RELOCATE

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>


class elf_relocate{
public:
    elf_relocate(uint8_t* _elf_data, int _mode){
        elf_data = _elf_data;
        mode = _mode;
        plt_rela_sz_dyn = NULL;
        rela_sz_dyn = NULL;
        init_dyn = NULL;
        last_dyn = NULL;
        this->init();
    };

    void* get_rela(std::string symbol_name);
    bool remove_rela(std::string symbol_name);
    bool move_rela2end(std::string symbol_name);
    bool remove_last_rela();
    /*
    zeor if null
    */
    uint64_t get_init_offset();
    bool set_init_offset(uint64_t init_offset);
private:
    
    uint8_t* elf_data;
    void* dynamic;
    void* rela_;
    size_t rela_count_;
    void* plt_rela_;
    size_t plt_rela_count_;
    void* symtab_;
    const char* strtab_;
    void* plt_rela_sz_dyn;
    void* rela_sz_dyn;
    void* init_dyn;
    void* last_dyn;

    int mode;

    void init();
};

#endif