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
    // Fetch the signature length per byte
    u32 sig_len_per_byte  = get_sig_len_per_byte(style);
    i32 sig_len           = (bytes.size() * sig_len_per_byte);

    // Allocate the extra room for the mask
    if(style == SIGNATURE_STYLE_CODE && (n_settings::data & FLAG_INCLUDE_MASK_FOR_CODE_SIGS))
      sig_len += bytes.size();

    // Allocate room for the signature
    i8* sig = reinterpret_cast<i8*>(malloc(sig_len));
    memset(sig, 0, sig_len);

    for(u32 i = 0; i < bytes.size(); i++){
      if((strlen(sig) + sig_len_per_byte) > sig_len){
        warning("[Fusion] `0x%llX` Has a bugged signature buffer (0)", sig);
        break;
      }

      if(style == SIGNATURE_STYLE_IDA){
        if(i > 0)
          qsnprintf(sig + strlen(sig), sig_len_per_byte, " ");

        qsnprintf(sig + strlen(sig), sig_len_per_byte, imm[i] ? ((n_settings::data & FLAG_USE_DUAL_QUESTION_MARKS) ? "??" : "?") : "%02X", (u8)bytes[i]);
      }
      else if(style == SIGNATURE_STYLE_CODE)
        qsnprintf(sig + strlen(sig), sig_len_per_byte, imm[i] ? "\\x00" : "\\x%02X", (u8)bytes[i]);
    }

    // Add the code signature mask onto the signature
    if(style == SIGNATURE_STYLE_CODE && (n_settings::data & FLAG_INCLUDE_MASK_FOR_CODE_SIGS)){
      // Add a space between the signature and the mask
      qsnprintf(sig + strlen(sig), sig_len_per_byte, " ");

      for(u32 i = 0; i < bytes.size(); i++){
        if((strlen(sig) + sig_len_per_byte) > sig_len){
          warning("[Fusion] `0x%llX` Has a bugged signature buffer (1)", sig);
          break;
        }

        qsnprintf(sig + strlen(sig), sig_len_per_byte, imm[i] ? "?" : "x");
      }
    }

    return sig;
  }
};
