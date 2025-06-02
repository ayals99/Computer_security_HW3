#define _XOPEN_SOURCE 500
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <limits.h>
#include <unistd.h>
#include <ftw.h>

static const int MAX_FD_AMOUNT = 16;
static const unsigned int COMPSEC_MIN_CLASS = 0;
static const unsigned int COMPSEC_MAX_CLASS = 3;
static const int MAX_NUMBER_OF_ARGS = 5;
static const int MIN_NUMBER_OF_ARGS = 4;
static int global_class_int;
static const char COMPSEC_EA_NAME[] = "security.compsec";

void print_usage(const char* program_name) {
	fprintf(stderr, "Usage: %s -c class [-r] filename\n", program_name);
}

int validate_filename(char *filename) {
	if (access(filename, F_OK) != 0) {
		// file doesn't exist
		return -1;
	}
	return 0;
}
int is_valid_class_number(long class) {
	if (class > COMPSEC_MAX_CLASS || class < COMPSEC_MIN_CLASS)
	  return 0;
	return 1;
}

int validate_class(char* class, unsigned int *class_int) {
	int ret = 0;
	char *p = NULL;
	int conversion_base = 10;
	errno = 0;

	long conversion = strtol(class, &p, conversion_base);
	if (errno) {
		perror("compsec: Class conversion error");
		return -1;
	}
	else if (*p) {
		perror("compsec: Not all characters converted in class");
		return -1;
	}
	if (!is_valid_class_number(conversion)){
		printf("compsec: please input a valid class [0-3]\n");
		return -1;
	}
	
	*class_int = (unsigned int) conversion;

	return 0;
}

int validate_user_input(char *filename, char *class, unsigned int *class_int) {
	return validate_filename(filename) || validate_class(class, class_int);
}

int aux_set_class(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	if (setxattr(fpath, COMPSEC_EA_NAME, &global_class_int, sizeof(unsigned int), 0) != 0) {
		perror(fpath);
	}
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc > MAX_NUMBER_OF_ARGS || argc < MIN_NUMBER_OF_ARGS ) {
		print_usage(argv[0]);
		return 1;
	}
	
	int opt;
	char *class = NULL;
	char *filename = NULL;
	char file_path [PATH_MAX];
	int recursive_flag = 0;
	int ret = 0;
	unsigned int class_int = 0;
	ssize_t len = 0;
	unsigned int current_file_class = COMPSEC_MAX_CLASS + 1;
	
	while ((opt = getopt(argc, argv, "c:r")) != -1) {
		switch (opt) {
			case 'c':
				class = optarg;
				break;
			case 'r':
				recursive_flag = 1;
				break;
			default:
				print_usage(argv[0]);
				return 1;
		}
	}
	
	if (optind >= argc || class == NULL) {
		print_usage(argv[0]);
		return 1;
	}

	filename = argv[optind];

	ret = validate_user_input(filename, class, &class_int);
	if (ret) {
		return ret;
	}

	// For Debug:
	// printf("Class: %u\n", class_int);
	// printf("Recursive: %s\n", recursive_flag ? "Yes" : "No");
	// printf("Filename: %s\n", filename);

	char *found_path = realpath(filename, file_path);
	if (!found_path) {
		return 1;
	}

	if (recursive_flag) {
		global_class_int = class_int;
		ret = nftw(file_path, aux_set_class, MAX_FD_AMOUNT, FTW_PHYS);
		return ret;
	}

	len = getxattr(file_path, COMPSEC_EA_NAME, &current_file_class, sizeof(unsigned int));
	if (len == sizeof(current_file_class) && class_int < current_file_class) {
		printf("compsec: Lower class from %u to %u? [y/n]\n",current_file_class, class_int);
		char answer;
		scanf("%c", &answer);
		if (answer != 'y')
			return 1;
	}

	if (setxattr(file_path, COMPSEC_EA_NAME, &class_int, sizeof(unsigned int), 0) != 0) {
		return 1;
	}

	return ret;
}
