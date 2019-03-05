#include <iostream>
#include <stdio.h>
#include "elf_parser.h"
#include "elf_relocate.h"

class elf_patch{
public:
    elf_patch(std::string _target_so, std::string _sutb_path):
    stub(_sutb_path), target_so(_target_so){};

    
    bool patch_stub();
private:
    elf_parser::Elf_parser stub;
    elf_parser::Elf_parser target_so;

    bool memery_copy(uint8_t* target, uint64_t target_len, uint8_t* stub, uint64_t stub_len, uint64_t offset);
};
