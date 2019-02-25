#include <iostream>
#include "elf_parser.h"
#include <stdio.h>
#include <unistd.h>

void print_symbols(std::vector<elf_parser::symbol_t> &symbols) {
    std::cout <<"print symbols : " <<std::endl;
    int i=0;
    for (auto &symbol : symbols) {
        std::cout <<"["<<i++<<"]"<<"  section name:" << symbol.symbol_name << "  vaddr:0x" <<std::hex<<symbol.symbol_value <<std::endl;
    }
}

void print_sections(std::vector<elf_parser::section_t> &sections){
    for(auto &section : sections){
        std::cout << section.section_name << "  vaddr:0x" << std::hex <<section.section_offset << "  size:0x" << section.section_size << std::endl;
    }
}



int main(int argc, char* argv[]){
    std::string filepath(argv[1]);
    elf_parser::Elf_parser elf(filepath);
    std::vector<elf_parser::symbol_t> symbols = elf.get_symbols();
    unsigned long offset = elf.getSymbolOffset("read_elf");

    unsigned char orig_data[4] = {0xbe, 0xef, 0xbe, 0xef};
    
    if(elf.remove_symbol("getchar")){
        LOGI("remove symbol ok");
    }else{
        LOGE("remove symbol fail...");
        return -1;
    }

    if(elf.replace_data(orig_data, sizeof(orig_data), offset)){
        LOGI("replace magic ok");
    }else{
        LOGE("replace magic fail");
        return -1;
    }

    if(elf.update_file()){
        LOGI("update file ok");
    }else{
        return -1;
    }
    
    return 0;
}

