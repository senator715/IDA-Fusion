#pragma once

enum e_settings_flags{
  FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES      = 1 << 0, // Auto jump to the first signature address found
  FLAG_COPY_SELECTED_BYTES_ONLY_IN_RANGE  = 1 << 1, // When a region is selected in the current screen view, explicitly create a signature for these bytes
  FLAG_SHOW_MNEMONIC_OPCODES_SIGGED       = 1 << 2, // Shows the mnemonics for all of the byes in the signature
  FLAG_COPY_CREATED_SIGNATURES_TO_CB      = 1 << 3, // Copy any created signatures to the clipboard automatically
  FLAG_INCLUDE_MASK_FOR_CODE_SIGS         = 1 << 4, // Include the mask for code signatures
};

// Extern plugin_run so we can call it
EXTERN bool idaapi plugin_run(size_t arg);

namespace n_settings{
  u32 data = FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES | FLAG_COPY_SELECTED_BYTES_ONLY_IN_RANGE | FLAG_SHOW_MNEMONIC_OPCODES_SIGGED | FLAG_COPY_CREATED_SIGNATURES_TO_CB;

  bool show_settings_dialog(){
    bool form_ok = ask_form(
      "Fusion — Settings\n"
      "<#Auto jump to found signatures:C>\n"
      "<#Explicitly copy selected bytes only when in a range:C>\n"
      "<#Show mnemonic opcodes when creating signatures:C>\n"
      "<#Copy created signatures to clipboard:C>\n"
      "<#Include mask for code signatures (xx??xx):C>>\n"
    , &data);

    plugin_run(0);
    return form_ok;
  }
};