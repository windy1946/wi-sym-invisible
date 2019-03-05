#include <iostream>
#include "elf_patch.h"
#include <stdio.h>
#include <unistd.h>
#include "log.h"

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
    std::string targetso(argv[1]);
    std::string stubso(argv[2]);

    LOGI("data init");

    elf_patch elf(targetso, stubso);
    
    LOGI("stub patch begin");
    
    if(!elf.patch_stub()){
        return -1;
    }
    
    return 0;
}

