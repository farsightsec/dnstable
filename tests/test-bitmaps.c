#include <sys/types.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wdns.h>
#include "dnstable/dnstable.h"
#include "dnstable/dnstable-private.h"
#include "libmy/hex_decode.h"

char *strip_non_alpha(const char *input);

static void
usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\ttest-bitmaps [-e RRtypes] [-d hex-pairs]\n"
		"\n"
		"Flags:\n"
		"\t-d: hex pairs of digits to treat as a bitmap to decode.\n"
		"\t    If two digits (one byte) then it is a one byte RRtype.\n"
		"\t    If four digits (two bytes) then it is a two byte RRtype\n"
		"\t    in little-endian order.\n"
		"\t    Otherwise, then it is a RFC4034 4.1.2 bitmap.\n"
		"\t    Embedded space and puncuation are ignored.\n"
		"\t-e: space separated list of RRtypes to encode\n"
		"\n"
		"One of -e or -d is required\n");

	exit(EXIT_FAILURE);
}

static int decode_test(uint8_t *decode_this, size_t decode_len)
{
	rrtype_unpacked_set result_rrtypes;
	int num_rrtypes = rrtype_union_unpack(decode_this, decode_len, &result_rrtypes);

	if (num_rrtypes == -1) {
		fprintf(stderr, "rrtype_bitmap_unpack failed\n");
		return EXIT_FAILURE;
	}

	if (num_rrtypes == 0) {
		fprintf(stderr, "rrtype_bitmap_unpack found no rrtypes bits set or valid\n");
		return EXIT_FAILURE;
	}

	for (int i = 0; i < num_rrtypes; i++) {
		const char *s_rtype = wdns_rrtype_to_str(result_rrtypes.rrtypes[i]);
		printf("rrtype = %d = %s\n", result_rrtypes.rrtypes[i], s_rtype != NULL ? s_rtype : "(not assigned)");
	}
	return EXIT_SUCCESS;
}


static int encode_test(const char *encode_this)
{
	wdns_res w_res;
	uint8_t *encoding = 0;
	size_t len;
	char buf[10240];

	/*
	 * The "1 1 0 - 00 %s " is an NSEC3 rdata value, as a string.
	 * Given encode_this = "A", this will result in
	 * 01-01-00-00-00-02-00-00-00-01-40
	 * where the trailing 00-01-40 is the rrtype bitmap.
	 * so we extract starting from index 8 in the returned value.
	 * Note: the trailing space is important, otherwise there will be a parse error.
	 */
	assert((unsigned)snprintf(buf, sizeof(buf) - 1, "1 1 0 - 00 %s ", encode_this) < sizeof(buf));
	w_res = wdns_str_to_rdata(buf, WDNS_TYPE_NSEC3, WDNS_CLASS_IN, (uint8_t **) &encoding, &len);
	if (w_res == wdns_res_parse_error) {
		fprintf(stderr, "wdns_str_to_rdata returned a wdns_res_parse_error -- are the RRtypes all valid?\n");
		return EXIT_FAILURE;
	} else if (w_res != wdns_res_success) {
		fprintf(stderr, "wdns_str_to_rdata returned an unknown wdns error %d\n", (int) w_res);
		return EXIT_FAILURE;
	}

	printf("bitmap: ");
	for (size_t i = 8; i < len; i++) {
		printf("%02x", encoding[i]);
	}
	printf("\n");
	free(encoding);
	return EXIT_SUCCESS;
}

/*
 * Return input with any non-alpha numeric characters striped out.
 * Will return NULL if no characters are alpha numeric.
 */
char *
strip_non_alpha(const char *input)
{
	assert(input != NULL);
	size_t num_chars = 0;
	const char *cp;
	for (cp = input; *cp != '\0'; cp++)
		if (isalnum(*cp))
			num_chars++;
	if (num_chars == 0)
		return NULL;
	char *result = malloc(num_chars + 1);
	char *rp = result;
	for (cp = input; *cp != '\0'; cp++)
		if (isalnum(*cp))
			*rp++ = *cp;
	*rp++ = '\0';
	return result;
}

int
main(int argc, char **argv)
{
	int ch;
	uint8_t *decode_this = NULL;
	size_t decode_len = 0;
	const char *encode_this = NULL;

	while ((ch = getopt(argc, argv, "d:e:")) != -1) {
		switch (ch) {
		case 'd':
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Need a non-empty argument to -d\n");
				return EXIT_FAILURE;
			}
			char *stripped = strip_non_alpha(optarg);
			if (stripped == NULL) {
				fprintf(stderr, "hex pairs decoding of %s failed\n", optarg);
				return EXIT_FAILURE;
			}
			if (hex_decode(stripped, &decode_this, &decode_len) == false) {
				fprintf(stderr, "hex pairs decoding of %s failed\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'e':
			encode_this = strdup(optarg);
			break;
		case -1:
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || (encode_this == NULL && decode_this == NULL))
		usage();

	if (encode_this != NULL)
		if (encode_test(encode_this) != EXIT_SUCCESS)
			return EXIT_FAILURE;

	if (decode_this != NULL)
		if (decode_test(decode_this, decode_len) != EXIT_SUCCESS)
			return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
