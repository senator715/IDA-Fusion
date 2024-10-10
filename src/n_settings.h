#pragma once

enum e_settings_flags{
  FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES      = 1 << 0, // Auto jump to the first signature address found
  FLAG_COPY_SELECTED_BYTES_ONLY_IN_RANGE  = 1 << 1, // When a region is selected in the current screen view, explicitly create a signature for these bytes
  FLAG_SHOW_MNEMONIC_OPCODES_SIGGED       = 1 << 2, // Shows the mnemonics for all of the bytes in the signature
  FLAG_COPY_CREATED_SIGNATURES_TO_CB      = 1 << 3, // Copy any created signatures to the clipboard automatically
  FLAG_INCLUDE_MASK_FOR_CODE_SIGS         = 1 << 4, // Include the mask for code signatures
  FLAG_ALLOW_SIG_CREATION_IN_DR           = 1 << 5, // Allow signature creation in unknown, dangerous regions (assembly marked in red)
  FLAG_STOP_AT_FIRST_SIGNATURE_FOUND      = 1 << 6, // Stop searching after one signature has been found
  FLAG_USE_DUAL_QUESTION_MARKS            = 1 << 7, // Use "??" as wildcard instead of "?" for IDA style signatures
  FLAG_USE_UNICODE_WILDCARD               = 1 << 8, // Use "2A" as wildcard instead of "00" for CODE style signatures
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
      "<#Include mask for code signatures (xx??xx):C>\n"
      "<#Allow signature creation in regions marked as red (DANGEROUS):C>\n"
      "<#Do not return multiple results for signature searches:C>\n"
      "<#Use \"??\" as wildcard for IDA style signatures:C>\n"
      "<#Use \"2A\" as wildcard for CODE style signatures:C>>\n"
    , &data);

    plugin_run(0);
    return form_ok;
  }
};
