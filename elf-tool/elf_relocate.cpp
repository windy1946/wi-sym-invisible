#include "elf_relocate.h"
#include "log.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

void elf_relocate::init(){
    if(this->mode == 64){
        Elf64_Ehdr *ehdr = (Elf64_Ehdr*)this->elf_data;
        Elf64_Phdr* phdr_table = (Elf64_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff);
        size_t phdr_num = ehdr->e_phnum;
        
        for (size_t i = 0; i<phdr_num; ++i) {
            const Elf64_Phdr* phdr = (Elf64_Phdr*)&phdr_table[i];
            if (phdr->p_type == PT_DYNAMIC) {
                dynamic = (Elf64_Dyn*)((uint8_t*)this->elf_data + phdr->p_offset);
                break;
            }
        }

        int i=0;
        Elf64_Dyn* dyn = NULL;
        for(dyn = (Elf64_Dyn*)dynamic; dyn->d_tag != DT_NULL; dyn++ ){
            switch(dyn->d_tag){
                case DT_RELA:
                    rela_ = (Elf64_Rela*)((uint8_t*)this->elf_data + (dyn->d_un.d_ptr));  // + load_bias  ????
                break; 
                case DT_RELASZ:
                    //LOGD("relasz...");
                    rela_count_ =  (Elf64_Word)dyn->d_un.d_val / sizeof(Elf64_Rela);
                    this->rela_sz_dyn = dyn;
                    //LOGD("relasz : %ld", rel_count_);
                    break;
                case DT_SYMTAB:
                    //LOGD("symtab...");
                    symtab_ = (Elf64_Sym*)((uint8_t*)this->elf_data + (Elf64_Addr)(dyn->d_un.d_ptr));  // + load_bias   ???
                    break;
                case DT_STRTAB:
                    //LOGD("strtab...");
                    strtab_ = (const char*)((uint8_t*)this->elf_data + (Elf64_Addr)dyn->d_un.d_ptr);  // + load_bias   ???
                    break;
                case DT_JMPREL:
                    plt_rela_ = (Elf64_Rela*)((uint8_t*)this->elf_data + (Elf64_Addr)dyn->d_un.d_ptr);
                    break;
                case DT_PLTRELSZ:
                    plt_rela_count_ = (Elf64_Word)dyn->d_un.d_val / sizeof(Elf64_Rela);
                    this->plt_rela_sz_dyn = dyn;
                    break;
                default:
                    break;
            }
        }
    }
};

bool elf_relocate::move_rela2end(std::string symbol_name){
    LOGD("mode : %d", this->mode);
    if(this->mode == 64){
        Elf64_Rela* r = (Elf64_Rela*)this->rela_;
        Elf64_Sym* s = (Elf64_Sym*)this->symtab_;
        for(size_t i=0; i<this->rela_count_; i++){
            Elf64_Xword sym_index = ELF64_R_SYM(r[i].r_info);
            //LOGD("r_info :%ld", r[i].r_info);
            //LOGD("sym_index :%ld", sym_index);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            //LOGD("symbol name : %s", sym_name);
            if(std::string(sym_name) == symbol_name){
                Elf64_Rela* cur_rela = (Elf64_Rela*)&r[i];
                Elf64_Rela* end_rela = (Elf64_Rela*)&r[rela_count_-1];
                Elf64_Rela* temp = (Elf64_Rela*)malloc(sizeof(Elf64_Rela));
                memcpy(temp, end_rela, sizeof(Elf64_Rela));
                memcpy(end_rela, cur_rela, sizeof(Elf64_Rela));
                memcpy(cur_rela, temp, sizeof(Elf64_Rela));
                this->plt_rela_sz_dyn = NULL;
                return true;
            }
        }
        r = (Elf64_Rela*)this->plt_rela_;
        for(size_t i=0; i<this->plt_rela_count_; i++){
            Elf64_Xword sym_index = ELF64_R_SYM(r[i].r_info);
            //LOGD("r_info :%ld", r[i].r_info);
            //LOGD("sym_index :%ld", sym_index);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            //LOGD("symbol name : %s", sym_name);
            if(std::string(sym_name) == symbol_name){
                //LOGD("remove symbol name : %s", sym_name);
                Elf64_Rela* cur_rela = (Elf64_Rela*)&r[i];
                Elf64_Rela* end_rela = (Elf64_Rela*)&r[plt_rela_count_-1];
                Elf64_Rela* temp = (Elf64_Rela*)malloc(sizeof(Elf64_Rela));
                memcpy(temp, end_rela, sizeof(Elf64_Rela));
                memcpy(end_rela, cur_rela, sizeof(Elf64_Rela));
                memcpy(cur_rela, temp, sizeof(Elf64_Rela));
                this->rela_sz_dyn = NULL;
                return true;
            }
        }
    }else if(this->mode == 32){
        Elf32_Rela* r = (Elf32_Rela*)this->rela_;
        Elf32_Sym* s = (Elf32_Sym*)this->symtab_;
        for(size_t i=0; i<rela_count_; i++){
            Elf32_Xword sym_index = ELF32_R_SYM(r[i].r_info);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            if(std::string(sym_name) == symbol_name){
                Elf32_Rela* cur_rela = (Elf32_Rela*)&r[i];
                Elf32_Rela* end_rela = (Elf32_Rela*)&r[rela_count_-1];
                Elf32_Rela* temp = (Elf32_Rela*)malloc(sizeof(Elf32_Rela));
                memcpy(temp, end_rela, sizeof(Elf32_Rela));
                memcpy(end_rela, cur_rela, sizeof(Elf32_Rela));
                memcpy(cur_rela, temp, sizeof(Elf32_Rela));
                return true;
            }
        }
        r = (Elf32_Rela*)this->plt_rela_;
        for(size_t i=0; i<plt_rela_count_; i++){
            Elf32_Xword sym_index = ELF32_R_SYM(r[i].r_info);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            if(std::string(sym_name) == symbol_name){
                Elf32_Rela* cur_rela = (Elf32_Rela*)&r[i];
                Elf32_Rela* end_rela = (Elf32_Rela*)&r[plt_rela_count_-1];
                Elf32_Rela* temp = (Elf32_Rela*)malloc(sizeof(Elf32_Rela));
                memcpy(temp, end_rela, sizeof(Elf32_Rela));
                memcpy(end_rela, cur_rela, sizeof(Elf32_Rela));
                memcpy(cur_rela, temp, sizeof(Elf32_Rela));
                return true;
            }
        }
    }

    return false;
}

void* elf_relocate::get_rela(std::string symbol_name)
{
    if(this->mode == 64){
        Elf64_Rela* r = (Elf64_Rela*)this->rela_;
        Elf64_Sym* s = (Elf64_Sym*)this->symtab_;
        for(size_t i=0; i<this->rela_count_; i++){
            Elf64_Xword sym_index = ELF64_R_SYM(r[i].r_info);
            //LOGD("r_info :%ld", r[i].r_info);
            //LOGD("sym_index :%ld", sym_index);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            if(std::string(sym_name) == symbol_name){
                return &r[i];
            }
        }
        r = (Elf64_Rela*)this->plt_rela_;
        for(size_t i=0; i<this->plt_rela_count_; i++){
            Elf64_Xword sym_index = ELF64_R_SYM(r[i].r_info);
            //LOGD("r_info :%ld", r[i].r_info);
            //LOGD("sym_index :%ld", sym_index);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            if(std::string(sym_name) == symbol_name){
                return &r[i];
            }
        }
    }else if(this->mode == 32){
        Elf32_Rela* r = (Elf32_Rela*)this->rela_;
        Elf32_Sym* s = (Elf32_Sym*)this->symtab_;
        for(size_t i=0; i<rela_count_; i++){
            Elf32_Xword sym_index = ELF32_R_SYM(r[i].r_info);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            if(std::string(sym_name) == symbol_name){
                return &r[i];
            }
        }
        r = (Elf32_Rela*)this->plt_rela_;
        for(size_t i=0; i<plt_rela_count_; i++){
            Elf32_Xword sym_index = ELF32_R_SYM(r[i].r_info);
            const char* sym_name = this->strtab_ + s[sym_index].st_name;
            if(std::string(sym_name) == symbol_name){
                return &r[i];
            }
        }
    }

    return NULL;
}


bool elf_relocate::remove_last_rela(){
    if(this->mode == 64){
        if(this->rela_sz_dyn != NULL){
            ((Elf64_Dyn*)this->rela_sz_dyn)->d_un.d_val -= sizeof(Elf64_Rela);
            return true;
        }else if(this->plt_rela_sz_dyn != NULL){
            ((Elf64_Dyn*)this->plt_rela_sz_dyn)->d_un.d_val -= sizeof(Elf64_Rela);
            return true;
        }
    }else if(this->mode == 32){
        if(this->rela_sz_dyn != NULL){
            ((Elf32_Dyn*)this->rela_sz_dyn)->d_un.d_val -= sizeof(Elf32_Rela);
            return true;
        }else if(this->plt_rela_sz_dyn != NULL){
            ((Elf32_Dyn*)this->plt_rela_sz_dyn)->d_un.d_val -= sizeof(Elf32_Rela);
            return true;
        } 
    }
    
    return false;
}

bool elf_relocate::remove_rela(std::string symbol_name){

    if(!this->move_rela2end(symbol_name)){
        LOGE("move rela to the end fail...");
        return false;
    }
    
    if(!this->remove_last_rela()){
        LOGE("remove the last rela fail...");
        return false;
    }

    return true;
}