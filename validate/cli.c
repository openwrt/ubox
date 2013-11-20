#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/stat.h>

#include <uci.h>

#include "libvalidate.h"

static void
print_usage(char *argv)
{
	fprintf(stderr, "%s <datatype> <value>\t- validate a value against a type\n", argv);
	fprintf(stderr, "%s <package> <section_type> <section_name> 'option:datatype:default' 'option:datatype:default' ...\n", argv);
}

static char*
bool_to_num(char *val)
{
	static char val0[] = "0";
	static char val1[] = "1";
	static char val_none[] = "";

	if (!strcmp(val, "0") || !strcmp(val, "off") || !strcmp(val, "false") || !strcmp(val, "disabled"))
		return val0;
	if (!strcmp(val, "1") || !strcmp(val, "on") || !strcmp(val, "true") || !strcmp(val, "enabled"))
		return val1;

	return val_none;
}

static int
validate_option(struct uci_context *ctx, char *package, char *section, char *option)
{
	char *datatype = strstr(option, ":");
	struct uci_ptr ptr = { 0 };
	char *val;
	int ret = 0;

	if (!datatype) {
		fprintf(stderr, "%s is not a valid option\n", option);
		return -1;
	}

	*datatype = '\0';
	datatype++;
	val = strstr(datatype, ":");
	if (val) {
		*val = '\0';
		val++;
	}

	ptr.package = package;
	ptr.section = section;
	ptr.option = option;

	if (!uci_lookup_ptr(ctx, &ptr, NULL, false))
		if (ptr.flags & UCI_LOOKUP_COMPLETE)
			if (ptr.last->type == UCI_TYPE_OPTION)
				if ( ptr.o->type == UCI_TYPE_STRING)
					if (ptr.o->v.string)
						val = ptr.o->v.string;

	if (val) {
		ret = dt_parse(datatype, val);
		fprintf(stderr, "%s.%s.%s=%s validates as %s with %s\n", package, section, option,
			val, datatype, ret ? "true" : "false");
	}

	if (ret && !strcmp(datatype, "bool"))
		printf("%s=%s; ", option, bool_to_num(val));
	else if (ret)
		printf("%s=%s; ", option, val);
	else
		printf("unset -v %s; ", option);

	return ret;
}

int
main(int argc, char **argv)
{
	struct uci_context *ctx;
	struct uci_package *package;
	int len = argc - 4;
	bool rv;
	int i;

	if (argc == 3) {
		rv = dt_parse(argv[1], argv[2]);
		fprintf(stderr, "%s - %s = %s\n", argv[1], argv[2], rv ? "true" : "false");
		return rv ? 0 : 1;
	} else if (argc < 5) {
		print_usage(*argv);
		return -1;
	}

	if (*argv[3] == '\0') {
		printf("json_add_object; ");
		printf("json_add_string \"package\" \"%s\"; ", argv[1]);
		printf("json_add_string \"type\" \"%s\"; ", argv[2]);
		printf("json_add_object \"data\"; ");

		for (i = 0; i < len; i++) {
			char *datatype = strstr(argv[4 + i], ":");
			char *def;

			if (!datatype)
				continue;
			*datatype = '\0';
			datatype++;
			def = strstr(datatype, ":");
			if (def)
				*def = '\0';
			printf("json_add_string \"%s\" \"%s\"; ", argv[4 + i], datatype);
		}
		printf("json_close_object; ");
		printf("json_close_object; ");

		return 0;
	}

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, argv[1], &package))
		return -1;

	for (i = 0; i < len; i++)
		validate_option(ctx, argv[1], argv[3], argv[4 + i]);

	return 0;
}
