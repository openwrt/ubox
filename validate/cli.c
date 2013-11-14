#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/stat.h>

#include "libvalidate.h"

int main(int argc, char **argv)
{
	bool rv;

	if (argc == 3) {
		rv = dt_parse(argv[1], argv[2]);

		printf("%s - %s = %s\n", argv[1], argv[2], rv ? "true" : "false");

		return rv ? 0 : 1;
	} else if (argc > 3) {

	}

	return 0;
}
