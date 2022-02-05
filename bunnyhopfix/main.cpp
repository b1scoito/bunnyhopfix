INT APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	std::atexit([] {
		std::this_thread::sleep_for(10s);
	});

	if (!g_bhopfix->fix())
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}