#pragma once

typedef char               i8;
typedef short              i16;
typedef int                i32;
typedef long long          i64;
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long      ul64;
typedef unsigned long long u64;

#if __x86_64__
typedef u64 uptr;
#else
typedef u32 uptr;
#endif

#define EXTERN extern "C"