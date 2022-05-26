#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <windows.h>
#include <regex>

// Include typedefs
#include "typedefs.h"

// IDA sdk specific
#define __NT__
#define __X64__
#include <loader.hpp>
#include <idp.hpp>
#include <search.hpp>

// Custom
#include "n_utils.h"
#include "n_settings.h"
#include "n_signature.h"