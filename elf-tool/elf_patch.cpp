#include "elf_patch.h"
#include "elf_relocate.h"
#include "log.h"

bool elf_patch::patch_stub(){
    uint64_t sb_offset = this->stub.getSymbolOffset("on_start");
    uint64_t tg_offset = this->target_so.getSymbolOffset("stub");

    if(sb_offset == 0){
        LOGE("can not find read_elf()");
    }
    if(tg_offset == 0){
        LOGE("can not find stub()");
    }

    uint64_t new_init = sb_offset + tg_offset;

    elf_relocate elftool(this->target_so.get_memory_map(), this->target_so.get_mode());
    uint64_t init_offset = elftool.get_init_offset();

    if(elftool.set_init_offset(new_init)){
        LOGI("hook init ok");
    }else{
        LOGE("hook init fail");
        return false;
    }
    uint64_t offset = 0;
    if(init_offset != 0){
        offset = new_init - init_offset;
    }
    unsigned char orig_data1[4] = {0xe0, 0xbe, 0xef, 0xbe};
    if(this->stub.replace_data(orig_data1, sizeof(orig_data1), offset)){
        LOGI("replace new-init 2 orig-init offset ok");
    }else{
        LOGE("replace new-init 2 orig-init offset fail");
        return false;
    }
    
    unsigned char orig_data2[4] = {0xe1, 0xbe, 0xef, 0xbe};
    uint64_t symbol_offset = this->stub.getSymbolOffset("wi_symbol");
    if(this->stub.replace_data(orig_data2, sizeof(orig_data2), symbol_offset + tg_offset)){
        LOGI("replace get_base_addr offset ok");
    }else{
        LOGE("replace get_base_addr offset fail");
        return false;
    }

    if(this->memery_copy(this->target_so.get_memory_map(), this->target_so.get_file_size(),
                      this->stub.get_memory_map(), this->stub.get_file_size(),
                      tg_offset))
    {
        LOGI("memery copy ok");
    }else{
        LOGE("memery copy fail");
        return false;
    }

    
    if(this->target_so.remove_symbol("getchar")){
        LOGI("remove symbol ok");
    }else{
        LOGE("remove symbol fail...");
        return true;
    }


    if(this->target_so.update_file()){
        LOGI("update file ok");
    }else{
        LOGE("update file fail");
        return false;
    }
    
    return true;
}

bool elf_patch::memery_copy(uint8_t* target, uint64_t target_len, uint8_t* stub, uint64_t stub_len, uint64_t offset){
    if(target_len < stub_len + offset){
        LOGE("stub too big");
        return false;
    }
    uint8_t* dest = target + offset;
    LOGD("stub len : %ld", stub_len);
    for(int i=0; i<stub_len; i++){
        dest[i] = stub[i]; 
    }

    return true;
}