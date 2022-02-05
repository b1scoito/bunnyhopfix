#pragma once

// definitions
#define WIN32_LEAN_AND_MEAN

// includes
#include <memory>
#include <vector>
#include <mutex>
#include <thread>
#include <iostream>
#include <algorithm>
#include <string_view>

using namespace std::chrono_literals;

#ifdef _WIN32
#include <Windows.h>
#endif

// headers
#include "var.hpp"
#include "console.hpp"
#include "memory.hpp"
#include "process.hpp"
#include "fix.hpp"