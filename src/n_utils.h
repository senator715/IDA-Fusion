#pragma once

namespace n_utils{
  inline i32 get_insn_imm_offset(insn_t* insn){
    for(u32 i = 0; i < UA_MAXOP; i++){
      op_t* op = &insn->ops[i];

      // Instruction contains invalid operand/opcode
      if(op->type == o_void)
        return 0;

      // Instruction contains relocated address
      if(op->offb > 0)
        return op->offb;
    }

    return 0;
  }

  inline void get_text_min_max(ea_t& ea_min, ea_t& ea_max){
    ea_min = inf_get_min_ea();
    ea_max = inf_get_max_ea();
  }

  inline void copy_to_clipboard(i8* buffer){
    u32   alloc_len = strlen(buffer) + 1;
    void* alloc     = GlobalAlloc(GMEM_FIXED, alloc_len);
    qstrncpy(reinterpret_cast<i8*>(alloc), buffer, alloc_len);

    OpenClipboard(nullptr);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, alloc);
    CloseClipboard();
  }
};