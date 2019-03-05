#ifndef H_ELF_PARSER
#define H_ELF_PARSER

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>    /* O_RDONLY */
#include <sys/stat.h> /* For the size of the file. , fstat */
#include <sys/mman.h> /* mmap, MAP_PRIVATE */
#include <vector>
#include <elf.h>      // Elf64_Shdr
#include <fcntl.h>
#include "log.h"

namespace elf_parser {

#define X86 10
#define X86_64 20
#define ARM 30
#define ARM_64 40

typedef struct {
    int section_index = 0; 
    std::intptr_t section_offset, section_addr;
    std::string section_name;
    std::string section_type; 
    int section_size, section_ent_size, section_addr_align;
    void* section_header;
} section_t;

typedef struct {
    std::string segment_type, segment_flags;
    long segment_offset, segment_virtaddr, segment_physaddr, segment_filesize, segment_memsize;
    int segment_align;
} segment_t;

typedef struct {
    std::string symbol_index;
    std::intptr_t symbol_value;
    int symbol_num = 0, symbol_size = 0;
    std::string symbol_type, symbol_bind, symbol_visibility, symbol_name, symbol_section;      
} symbol_t;

typedef struct {
    std::intptr_t relocation_offset, relocation_info, relocation_symbol_value;
    std::string   relocation_type, relocation_symbol_name, relocation_section_name;
    std::intptr_t relocation_plt_address;
} relocation_t;


class Elf_parser {
    public:
        Elf_parser (std::string &program_path): m_program_path{program_path} {   
            load_memory_map();
        }
        std::vector<section_t> get_sections();
        std::vector<segment_t> get_segments();
        std::vector<symbol_t> get_symbols();
        std::vector<relocation_t> get_relocations();

        uint64_t getSymbolOffset(std::string symbolname);
        uint8_t *get_memory_map();
        
        bool replace_data(unsigned char* orig_data, size_t length, unsigned long src_data);
        bool remove_symbol(std::string symbol_name);

        int get_mode(){return this->mode;}
        int get_type(){return this->type;}
        uint64_t get_file_size(){return this->file_size;}

        uint8_t *m_mmap_program;
        
        bool update_file();

        ~Elf_parser(){
            //release mmap
        }
    private:
        void load_memory_map();
        
        std::string get_section_type(int tt);
        void* get_symbol(std::string symbol_name);
        void* get_symbol(std::string symbol_name, int& symbol_index);
        

        std::string get_segment_type(uint32_t &seg_type);
        std::string get_segment_flags(uint32_t &seg_flags);

        std::string get_symbol_type(uint8_t &sym_type);
        std::string get_symbol_bind(uint8_t &sym_bind);
        std::string get_symbol_visibility(uint8_t &sym_vis);
        std::string get_symbol_index(uint16_t &sym_idx);

        std::string get_relocation_type(uint64_t &rela_type);
        
        std::intptr_t get_rel_symbol_value(uint64_t &sym_idx, std::vector<symbol_t> &syms);
        std::string get_rel_symbol_name(uint64_t &sym_idx, std::vector<symbol_t> &syms);

        int find_magic(const char* magic, int magic_len);
        bool set_dynsym(void* symbol_table, int len);
        bool set_strtab(void* symbol_name, int len);
        bool set_relo(void* relo_table, int len);
        
        std::string m_program_path; 
        unsigned long file_size;
        int mode;
        int type;

};

}
#endif