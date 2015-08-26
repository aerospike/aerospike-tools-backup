#include <stdio.h>

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
	puts("-gdwarf-4");
#else
	puts("-gdwarf-2");
#endif

	return 0;
}
