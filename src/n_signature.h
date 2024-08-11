#pragma once

// Include our signature generator
#include "c_signature_generator.h"

struct s_signature_find_settings{
  bool silent             = true;   // Output information
  bool stop_at_first      = false;  // Stop at first found signature
  ea_t ignore_addr        = 0;      // Ignore a selected address
  ea_t start_at_addr      = 0;      // Start scanning from an address
  bool jump_to_found_addr = false;  // Jump to the found address
};

namespace n_signature{
  static std::vector<ea_t> find(std::string signature, s_signature_find_settings find_settings){
    std::vector<ea_t> ea;

    // Handle the conversion of a code style sig to an IDA one if required
    if(strstr(signature.c_str(), "\\x")){
      // Fistly, convert \x to a space
      signature = std::regex_replace(signature, std::regex("\\\\x"), " ");

      // Remove any masks before converting 00's to a ?
      signature = std::regex_replace(signature, std::regex("x"), "");
      signature = std::regex_replace(signature, std::regex("\\?"), "");

      // Convert any 00's to ?
      signature = std::regex_replace(signature, std::regex("00"), "?");

      // Remove first space if there is one
      if(signature[0] == ' ')
        signature.erase(0, 1);
    }
    
    if(!find_settings.silent){
      hide_wait_box();
      show_wait_box("[Fusion] Searching...");
    }

    ea_t ea_min = 0;
    ea_t ea_max = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    compiled_binpat_vec_t sig_data{};
    parse_binpat_str(&sig_data, ea_min, signature.c_str(), 16);

    ea_t addr = (find_settings.start_at_addr > 0 ? find_settings.start_at_addr : ea_min) - 1;
    while(true){
      addr = bin_search3(addr + 1, ea_max, sig_data, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD);

      if(addr == 0 || addr == BADADDR)
        break;

      if(addr == find_settings.ignore_addr)
        continue;

      // Jump to the first address we find
      if(find_settings.jump_to_found_addr && ea.empty())
        jumpto(addr);

      ea.push_back(addr);

      if(!find_settings.silent){
        replace_wait_box("[Fusion] Searching...\n\nFound %i signature%s", ea.size(), ea.size() > 1 ? "s" : "");
        msg("[Fusion] %i. Found at address `0x%llX`\n", ea.size(), addr);
      }

      if(find_settings.stop_at_first)
        break;
    }

    if(!find_settings.silent){
      hide_wait_box();

      if(ea.empty())
        msg("[Fusion] No addresses found from signature\n", addr);
      else if(ea.size() > 1)
        msg("[Fusion] Found %i addresses\n", ea.size());

      beep(beep_default);
    }

    return ea;
  }

  static void create(e_signature_style style){
    if(!(n_settings::data & FLAG_ALLOW_SIG_CREATION_IN_DR) && get_func_num(get_screen_ea()) == 0xFFFFFFFF){
      hide_wait_box();
      warning("[Fusion] `0x%llX` Is not in a valid assembly region.\n\nHint: You can disable this in the settings of Fusion.", get_screen_ea());
      return;
    }

    c_signature_generator signature_generator;
    ea_t                  ea_region_start = 0;
    ea_t                  ea_region_end   = 0;
    ea_t                  ea_min          = 0;
    ea_t                  ea_max          = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    // Display a status that we are creating a signature for our screen ea
    replace_wait_box("[Fusion] Creating signature for `0x%llX`");

    // If we have selected a range of assembly code, then specifically sig that code only
    if((n_settings::data & FLAG_COPY_SELECTED_BYTES_ONLY_IN_RANGE) && read_range_selection(nullptr, &ea_region_start, &ea_region_end)){
      func_item_iterator_t iterator;
      iterator.set_range(ea_region_start, ea_region_end);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        insn_t insn;
        if(!decode_insn(&insn, addr))
          break;

        // Get the imm offset for this instruction
        i32 imm_offset = n_utils::get_insn_imm_offset(&insn);

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

      // Generate memory for the mnemonic opcodes list
      u32 mnemonic_opcodes_len  = 5000/*5KB*/;
      i8* mnemonic_opcodes      = (n_settings::data & FLAG_SHOW_MNEMONIC_OPCODES_SIGGED) ? (i8*)malloc(mnemonic_opcodes_len) : nullptr;

      if(mnemonic_opcodes != nullptr)
        memset(mnemonic_opcodes, 0, mnemonic_opcodes_len);

      func_item_iterator_t iterator;
      iterator.set_range(target_addr, ea_max);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        insn_t insn;
        if(!decode_insn(&insn, addr))
          break;

        // Get the imm offset for this instruction
        i32 imm_offset = n_utils::get_insn_imm_offset(&insn);

        // Now add the bytes to the signature generator
        for(ea_t op_addr = addr; op_addr < (addr + insn.size); op_addr++)
          signature_generator.add(get_byte(op_addr), imm_offset > 0 && (op_addr - addr) >= imm_offset);

        // Add details on whats going on in relation to this creation
        if(n_settings::data & FLAG_SHOW_MNEMONIC_OPCODES_SIGGED){
          qsnprintf(mnemonic_opcodes + strlen(mnemonic_opcodes), mnemonic_opcodes_len - strlen(mnemonic_opcodes), "+ %s\n", insn.get_canon_mnem(PH));
          replace_wait_box("[Fusion] Creating signature for `0x%llX`\n\n%s", target_addr, mnemonic_opcodes);
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

      if(mnemonic_opcodes != nullptr)
        free(mnemonic_opcodes);
    }

    // Do we have a signature to build?
    if(signature_generator.has_bytes){
      // Trim the signature
      signature_generator.trim();

      // Create a render of the signature in the selected style
      i8* signature = signature_generator.render(style);

      // Display
      msg("[Fusion] %s\n", signature);

      // Copy to clipboard
      if(n_settings::data & FLAG_COPY_CREATED_SIGNATURES_TO_CB)
        n_utils::copy_to_clipboard(signature);

      // Now free the rendered signature
      free(signature);

      beep(beep_default);
    }
  }
};