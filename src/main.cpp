#include "link.h"

bool idaapi plugin_run(size_t arg){
  static i32  choice  = 0;
  bool        form_ok = ask_form(
    "Fusion\n"
    "<#Generate signature (CODE Style):R>\n"
    "<#Generate signature (IDA Style):R>\n"
    "<#Search for a signature:R>\n"
    "<#Configure settings:R>>"
  , &choice);

  if(!form_ok)
    return true;

  switch(choice){
    case 0:{
      show_wait_box("[Fusion] Creating CODE signature...");
      n_signature::create(SIGNATURE_STYLE_CODE);
      hide_wait_box();
      break;
    }
    case 1:{
      show_wait_box("[Fusion] Creating IDA signature...");
      n_signature::create(SIGNATURE_STYLE_IDA);
      hide_wait_box();
      break;
    }
    case 2:{
      static i8 signature_to_find[1024];
      if(!ask_form(
        "Fusion — Enter signature\n"
        "<Signature:A5:1024:100>"
      , &signature_to_find))
        break;

      n_signature::find(signature_to_find, {false, static_cast<bool>(n_settings::data & FLAG_STOP_AT_FIRST_SIGNATURE_FOUND), 0, 0, static_cast<bool>(n_settings::data & FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES)});
      break;
    }
    case 3:{
      n_settings::show_settings_dialog();
      break;
    }
  }

  return true;
}

plugmod_t* idaapi plugin_init(void){
  return PLUGIN_OK;
}

EXTERN plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_PROC,
  plugin_init,
  nullptr,
  plugin_run,
  "ULTRA Fast Signature scanner & creator for IDA7 written with GCC",
  "https://github.com/senator715/IDA-Fusion",
  "Fusion",
  "Ctrl-Alt-S"
};