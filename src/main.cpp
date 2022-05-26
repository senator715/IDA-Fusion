#include "link.h"

bool idaapi plugin_run(size_t arg){
  static i32 choice = 0;
  if(!ask_form(
        "Fusion\n"
        "<#Generate signature (CODE Style):R>\n"
        "<#Generate signature (IDA Style):R>\n"
        "<#Search for a signature:R>>"
      , &choice))
    return true;

  if(choice == 0){
    show_wait_box("[Fusion] Creating CODE signature...");
    n_signature::create(SIGNATURE_STYLE_CODE);
    hide_wait_box();
  }
  else if(choice == 1){
    show_wait_box("[Fusion] Creating IDA signature...");
    n_signature::create(SIGNATURE_STYLE_IDA);
    hide_wait_box();
  }
  else if(choice == 2){
    static i8 signature_to_find[1024];
    if(!ask_form(
          "[Fusion] Enter signature\n"
          "<Signature:A5:1024:100>"
        , &signature_to_find))
      return true;

    n_signature::find(signature_to_find, {false, false, 0, 0, true});
  }

  return true;
}

plugmod_t* idaapi plugin_init(void){
  return PLUGIN_OK;
}

EXTERN plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_KEEP,
  plugin_init,
  nullptr,
  plugin_run,
  "ULTRA Fast Signature scanner & creator for IDA7 written in GCC",
  "https://github.com/senator715/IDA-Fusion",
  "Fusion",
  "Ctrl-Alt-S"
};