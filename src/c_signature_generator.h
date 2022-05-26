#pragma once

enum e_signature_style{
  SIGNATURE_STYLE_CODE = 0,
  SIGNATURE_STYLE_IDA  = 1
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

  // Memory returned from this function must be free'd
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