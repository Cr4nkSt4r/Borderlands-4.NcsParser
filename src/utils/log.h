/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#pragma once

#include <cstdarg>

namespace bl4::log {
void info(const char* fmt, ...);
void error(const char* fmt, ...);
}  // namespace bl4::log

#define BL4_LOG_INFO(fmt, ...) ::bl4::log::info(fmt, ##__VA_ARGS__)
#define BL4_LOG_ERROR(fmt, ...) ::bl4::log::error(fmt, ##__VA_ARGS__)
