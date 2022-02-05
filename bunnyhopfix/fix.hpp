#pragma once

#include <winternl.h>

class bunnyhopfix
{
public:
	bunnyhopfix() = default;
	~bunnyhopfix() = default;

    bool fix();

private:
};

inline auto g_bhopfix = std::make_unique<bunnyhopfix>();