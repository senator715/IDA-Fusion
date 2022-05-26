USE_COMPILER    =x86_64-w64-mingw32-g++
COMPILER_FLAGS  =-O3 -std=c++20 -s -w -Wreturn-type -fpermissive
LINKER_FLAGS    =-static -Wl,-exclude-all-symbols,--kill-at -shared
OUTPUT_FLAGS    =-o $(OUTPUT_FILE)
OBJ_DIR         =obj/
OBJ_FILES       =$(wildcard $(OBJ_DIR)*.o)

# Include IDA SDK
COMPILER_FLAGS += -Isdk/include

# This is the small trick for getting IDA's SDK to compile in GCC
ifeq ($(BUILD_FOR),32)
	COMPILER_FLAGS += -Lsdk/lib/x64_win_vc_32
else
	COMPILER_FLAGS += -Lsdk/lib/x64_win_vc_64
	COMPILER_FLAGS += -D__EA64__
endif

# Now include that vc library
LINKER_FLAGS   += -l:ida.lib

# Add core and custom directories to compile list
CPP_FILES      +=$(wildcard ./sdk/includes/*.cpp)
CPP_FILES      +=$(wildcard ./src/*.cpp)

.PHONY: make_objects $(CPP_FILES)

make_objects: $(CPP_FILES)
$(CPP_FILES):
	@printf "[!] $(@F)\n"
	@$(eval count=$(shell echo $$(($(count)+1))))
	@$(USE_COMPILER) $@ -c -o $(OBJ_DIR)$(count).o $(COMPILER_FLAGS)
	
make_output: $(OBJ_FILES)
	@printf "[+] $(notdir $(OUTPUT_FILE))\n"
	@$(USE_COMPILER) $(OUTPUT_FLAGS) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS)