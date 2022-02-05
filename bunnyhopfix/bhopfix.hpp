#pragma once

class bhopfix
{
public:
	bhopfix() = default;
	~bhopfix() = default;

    bool fix();
};

inline auto g_bhopfix = std::make_unique<bhopfix>();