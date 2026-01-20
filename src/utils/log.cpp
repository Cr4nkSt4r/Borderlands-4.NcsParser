/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "log.h"
#include <cstdio>

void vprint(FILE* f, const char* prefix, const char* fmt, va_list args) {
    std::fputs(prefix, f);
    std::vfprintf(f, fmt, args);
    std::fputc('\n', f);
    std::fflush(f);
}

namespace bl4::log {
void info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprint(stdout, "", fmt, args);
    va_end(args);
}

void error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprint(stderr, "[ERROR] ", fmt, args);
    va_end(args);
}
}  // namespace bl4::log
