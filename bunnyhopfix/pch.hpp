#pragma once

// definitions
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#endif

// includes
#include <mutex>
#include <memory>
#include <vector>
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
#include "bhopfix.hpp"