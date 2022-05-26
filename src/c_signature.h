#pragma once

enum e_signature_style{
  SIGNATURE_STYLE_CODE = 0,
  SIGNATURE_STYLE_IDA  = 1
};

struct  s_signature_find_settings{
  bool silent             = true;   // Output information
  bool stop_at_first      = false;  // Stop at first found signature
  ea_t ignore_addr        = 0;      // Ignore a selected address
  ea_t start_at_addr      = 0;      // Start scanning from an address
  bool jump_to_found_addr = false;  // Jump to the found address
};

class c_signature_generator{
public:
  bool              has_bytes = false;
  std::vector<u8>   bytes;
  std::vector<bool> imm;

  void reset(){
    bytes.clear();
    imm.clear();

    has_bytes = false;
  }

  // Trim the string of any imm signatures at the back and front of the signature
  void trim(){
    while(!imm.empty() && imm.back()){
      bytes.pop_back();
      imm.pop_back();
    }

    while(!imm.empty() && imm.front()){
      bytes.erase(bytes.begin());
      imm.erase(imm.begin());
    }

    has_bytes = !bytes.empty();
  }

  void add(u8 byte, bool is_imm = false){
    bytes.push_back(byte);
    imm.push_back(is_imm);

    has_bytes = true;
  }

  u32 get_sig_len_per_byte(e_signature_style style){
    if(style == SIGNATURE_STYLE_CODE)
      return 6;

    if(style == SIGNATURE_STYLE_IDA)
      return 4;

    error("[Fusion] get_sig_len_per_byte failed with %i\n", style);
    return -1;
  }

  i8* render(e_signature_style style){
    u32 sig_len_per_byte  = get_sig_len_per_byte(style);
    i32 sig_len           = (bytes.size() * sig_len_per_byte);
    i8* sig               = malloc(sig_len);
    memset(sig, 0, sig_len);

    for(u32 i = 0; i < bytes.size(); i++){
      if((strlen(sig) + sig_len_per_byte) > sig_len){
        warning("[Fusion] `0x%llX` Has a bugged signature buffer", sig);
        break;
      }

      if(style == SIGNATURE_STYLE_IDA){
        if(i > 0)
          qsnprintf(sig + strlen(sig), sig_len_per_byte, " ");

        qsnprintf(sig + strlen(sig), sig_len_per_byte, imm[i] ? "?" : "%02X", (u8)bytes[i]);
      }
      else if(style == SIGNATURE_STYLE_CODE)
        qsnprintf(sig + strlen(sig), sig_len_per_byte, imm[i] ? "\\x00" : "\\x%02X", (u8)bytes[i]);
    }

    return sig;
  }
};

class c_signature{
public:
  // Fetch imm offset from start of instruction
  i32 get_insn_imm_offset(insn_t* insn){
    for(u32 i = 0; i < UA_MAXOP; i++){
      op_t* op = &insn->ops[i];

      // Instruction contains invalid operand
      if(op->type == o_void)
        return 0;

      // Instruction contains relocated address
      if(op->offb > 0)
        return op->offb;
    }

    return 0;
  }

  void get_text_min_max(ea_t& ea_min, ea_t& ea_max){
    ea_min = inf_get_min_ea();
    ea_max = inf_get_max_ea();
  }

  void copy_to_clipboard(i8* buffer){
    u32   alloc_len = strlen(buffer) + 1;
    void* alloc     = GlobalAlloc(GMEM_FIXED, alloc_len);
    qstrncpy(alloc, buffer, alloc_len);

    OpenClipboard(nullptr);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, alloc);
    CloseClipboard();
  }

  std::vector<ea_t> find(std::string signature, s_signature_find_settings settings){
    std::vector<ea_t> ea;

    // Handle the conversion of a code style sig to an IDA one if required
    if(strstr(signature.c_str(), "\\x")){
      signature = std::regex_replace(signature, std::regex("\\\\x"), " ");
      signature = std::regex_replace(signature, std::regex("00"),    "?");

      if(signature[0] == ' ')
        signature.erase(0, 1);
    }

    if(!settings.silent){
      hide_wait_box();
      show_wait_box("[Fusion] Searching...");
    }

    ea_t ea_min, ea_max;
    get_text_min_max(ea_min, ea_max);

    ea_t addr = (settings.start_at_addr > 0 ? settings.start_at_addr : ea_min) - 1;
    while(true){
      addr = find_binary(addr + 1, ea_max, signature.c_str(), 16, SEARCH_DOWN);

      if(addr == 0 || addr == BADADDR)
        break;

      if(addr == settings.ignore_addr)
        continue;

      // Jump to the first address we find
      if(settings.jump_to_found_addr && ea.empty())
        jumpto(addr);

      ea.push_back(addr);

      if(!settings.silent){
        replace_wait_box("[Fusion] Searching...\n\nFound %i signature%s", ea.size(), ea.size() > 1 ? "s" : "");
        msg("[Fusion] %i. Found at address `0x%llX`\n", ea.size(), addr);
      }

      if(settings.stop_at_first)
        break;
    }

    if(!settings.silent){
      hide_wait_box();

      if(ea.empty())
        msg("[Fusion] No addresses found from signature\n", addr);
      else if(ea.size() > 1)
        msg("[Fusion] Found %i addresses\n", ea.size());

      beep(beep_default);
    }

    return ea;
  }

  void create(e_signature_style style){
    if(get_func_num(get_screen_ea()) == 0xFFFFFFFF){
      hide_wait_box();
      warning("[Fusion] `0x%llX` Is not in a valid assembly region.", get_screen_ea());
      return;
    }

    ea_t ea_min, ea_max;
    get_text_min_max(ea_min, ea_max);

    c_signature_generator signature_generator;
    ea_t                  ea_start = 0;
    ea_t                  ea_end   = 0;

    // If we have selected a range of assembly code, then specifically sig that code only
    if(read_range_selection(nullptr, &ea_start, &ea_end)){
      func_item_iterator_t iterator;
      iterator.set_range(ea_start, ea_end);

      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        insn_t insn;
        if(!decode_insn(&insn, addr))
          break;

        // Get the imm offset for this instruction
        i32 imm_offset = get_insn_imm_offset(&insn);

        // Now add the bytes to the signature generator
        for(ea_t op_addr = addr; op_addr < (addr + insn.size); op_addr++)
          signature_generator.add(get_byte(op_addr), imm_offset > 0 && (op_addr - addr) >= imm_offset);

        // These instructions are not parsed correctly by ida, so lets fix it
        if(get_byte(addr) == 0xCC || get_byte(addr) == 0x90){
          iterator.set_range(addr + 1, ea_max);
          continue;
        }

        if(!iterator.next_not_tail())
          break;
      }
    }
    else{
      ea_t target_addr        = get_screen_ea();
      ea_t last_found_address = ea_min;

      func_item_iterator_t iterator;
      iterator.set_range(target_addr, ea_max);

      u32 mnemonic_opcodes_len  = 5000/*5KB*/;
      i8* mnemonic_opcodes      = (i8*)malloc(mnemonic_opcodes_len);
      memset(mnemonic_opcodes, 0, mnemonic_opcodes_len);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        insn_t insn;
        if(!decode_insn(&insn, addr))
          break;

        // Get the imm offset for this instruction
        i32 imm_offset = get_insn_imm_offset(&insn);

        // Now add the bytes to the signature generator
        for(ea_t op_addr = addr; op_addr < (addr + insn.size); op_addr++)
          signature_generator.add(get_byte(op_addr), imm_offset > 0 && (op_addr - addr) >= imm_offset);

        // Add details on whats going on in relation to this creation
        {
          qsnprintf(mnemonic_opcodes + strlen(mnemonic_opcodes), mnemonic_opcodes_len - strlen(mnemonic_opcodes), "+ %s\n", insn.get_canon_mnem(ph));
          replace_wait_box("[Fusion] Creating signature for `0x%llX`\n\n%s\n", target_addr, mnemonic_opcodes);
        }

        // Attempt to search for this signature, if nothing is found then we have a unique signature
        {
          std::vector<ea_t> search_result = find(signature_generator.render(SIGNATURE_STYLE_IDA), {true, true, target_addr, last_found_address, false});
          if(search_result.empty())
            break;

          // Update the last found address so we dont have to scan that region anymore
          last_found_address = search_result[0];
        }

        // These instructions are not parsed correctly by ida, so lets fix it
        if(get_byte(addr) == 0xCC || get_byte(addr) == 0x90){
          iterator.set_range(addr + 1, ea_max);
          continue;
        }

        if(!iterator.next_not_tail())
          break;
      }

      free(mnemonic_opcodes);
    }

    // Do we have a signature to build?
    if(signature_generator.has_bytes){
      signature_generator.trim();
      i8* signature = signature_generator.render(style);
      msg("[Fusion] %s\n", signature);
      copy_to_clipboard(signature);
      free(signature);

      beep(beep_default);
    }
  }
};

extern c_signature* signature;