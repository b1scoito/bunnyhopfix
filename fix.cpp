#include "fix.hpp"

// TODO: Port memory class to process
bool bunnyhopfix::fix() {
	log_debug("Waiting for CS:S to open...");

	process proc = {};
	do 
	{
		proc = process::get_by_name(var::game::str_process);
		std::this_thread::sleep_for(250ms);
	} while (!proc.is_valid());

	auto cmd_line = proc.get_cmd_line();
	if (cmd_line.find(L"-insecure") == std::wstring::npos) 
	{
		log_err("-insecure argument not present, exiting!");
		return false;
	}

	log_debug("Attaching to process");
	g_mem->attach();

	log_debug("Waiting for client.dll to load...");
	std::pair<std::uintptr_t, std::uintptr_t> data{};
	do
	{
		g_mem->get_module(L"client.dll", data);
		std::this_thread::sleep_for(250ms);
	} while (data.first == 0x0);

	log_debug("Module address: 0x%x", data.first);

	// jnz jump_prediction
	// 0F 85 1A FF FF FF
	auto addr_jump_prediction = g_mem->pattern_scan(data.first, "\x85\xC0\x8B\x46\x08\x0F\x84\x00\xFF\xFF\xFF\xF6\x40\x28\x02\x0F\x85\x00\xFF\xFF\xFF", "xxxxxxx?xxxxxxxxx?xxx") + 15;
	log_debug("Jump prediction address: 0x%x", addr_jump_prediction);

	/* nop x 6 */
	uint8_t nop_chain[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

	if (addr_jump_prediction <= 0xf /* 15 */)  
	{
		log_err("Failed to find pattern address! (maybe already patched?)");
		return false;
	}

	log_debug("Applying patch");

	if (!g_mem->write(addr_jump_prediction, nop_chain, 6))
	{
		log_err("Failed to write memory!");
		return false;
	}

	log_ok("Done!");

	g_mem->unload();
	return true;
}