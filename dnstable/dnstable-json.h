/* Routines for jsonl serialization based on underlying ubuf encapsulation. */

#ifndef DNSTABLE_JSON_H
#define DNSTABLE_JSON_H

#include "libmy/my_alloc.h"
#include "libmy/ubuf.h"

static inline void
num_to_str(int num, int size, char * ptr) {
	int ndx = size - 1;

	while (size > 0) {
		int digit = num % 10;
		ptr[ndx] = '0' + digit;
		--ndx;
		--size;
		num /= 10;
	}
}

static inline size_t
vnum_to_str(uint64_t num, char *ptr) {
	uint64_t tmp = num;
	size_t ndx, left, ndigits = 0;

	do {
		ndigits++;
		tmp /= 10;
	} while (tmp != 0);

	left = ndigits;
	ndx = left - 1;
	while(left > 0) {
		int digit = num % 10;
		ptr[ndx] = '0' + digit;
		--ndx;
		--left;
		num = num/10;
	}

	ptr[ndigits] = '\0';

	return ndigits;
}

static inline void
declare_json_value(ubuf *u, const char *name, bool is_first) {
	if (!is_first)
		ubuf_append(u, (const uint8_t *)",\"", 2);
	else
		ubuf_append(u, (const uint8_t *)"\"", 1);

	ubuf_append(u, (const uint8_t *)name, strlen(name));
	ubuf_append(u, (const uint8_t *)"\":", 2);
}

static inline void
append_json_string_escaped(ubuf *u, const char *str, size_t len) {
	const char *scan, *scan_last, *scan_end;

	scan = scan_last = str;
	scan_end = str + len;

	while (scan < scan_end) {
		char esc = 0;

		switch (*(const unsigned char*) scan) {
			case '\b':
				esc = 'b';
				break;
			case '\f':
				esc = 'f';
				break;
			case '\n':
				esc = 'n';
				break;
			case '\r':
				esc = 'r';
				break;
			case '\t':
				esc = 't';
				break;
			case '"':
				esc = '"';
				break;
			case '\\':
				esc = '\\';
				break;
		}

		if (esc > 0 || *(const unsigned char*) scan <= 0x1f) {

			if (scan > scan_last)
				ubuf_append(u, (const uint8_t *)scan_last, (scan - scan_last));

			if (esc > 0) {
				char escbuf[2] = { '\\', esc };

				ubuf_append(u, (const uint8_t *)escbuf, 2);
			} else {
				char hexbuf[8];

				sprintf(hexbuf, "\\u00%.2x", *(const unsigned char*) scan);
				ubuf_append(u, (const uint8_t *)hexbuf, 6);
			}

			scan_last = scan + 1;
		}

		scan++;
	}

	ubuf_append(u, (const uint8_t *)scan_last, (scan_end - scan_last));
}

static inline void
append_json_value_string(ubuf *u, const char *val, size_t vlen) {
	ubuf_append(u, (const uint8_t *)"\"", 1);
	append_json_string_escaped(u, val, vlen);
	ubuf_append(u, (const uint8_t *)"\"", 1);	// guaranteed success x 3
}

/* More performant variant for when we know data doesn't need to be escaped. */
static inline void
append_json_value_string_noescape(ubuf *u, const char *val, size_t vlen) {
	ubuf_append(u, (const uint8_t *)"\"", 1);
	ubuf_append(u, (const uint8_t *)val, vlen);
	ubuf_append(u, (const uint8_t *)"\"", 1);	// guaranteed success x 3
}

static inline void
append_json_value_int(ubuf *u, uint64_t val) {
	char numbuf[32];
	size_t nlen;

	nlen = vnum_to_str(val, numbuf);
	ubuf_append(u, (const uint8_t *)numbuf, nlen);	// guaranteed succes
}

static inline void
append_json_value_bool(ubuf *u, bool val) {

	if (val)
		ubuf_append(u, (const uint8_t *)"true", 4);
	else
		ubuf_append(u, (const uint8_t *)"false", 5);	// guaranteed success
}

static inline void
append_json_value_double(ubuf *u, double val) {
	char dubbuf[64], *endp;
	size_t dlen;

	dlen = snprintf(dubbuf, sizeof(dubbuf), "%.18f", val);
	dubbuf[sizeof(dubbuf)-1] = 0;

	/* Trim possible trailing numerical zero padding */
	endp = dubbuf + dlen - 1;
	while (*endp != '\0' && endp > dubbuf) {
		if (*endp != '0' || *(endp-1) == '.')
			break;
		*endp-- = '\0';
		dlen--;
	}

	ubuf_append(u, (const uint8_t *)dubbuf, dlen);	// guaranteed success
}

static inline void
append_json_value_null(ubuf *u) {
	ubuf_append(u, (const uint8_t *)"null", 4);	// guaranteed success
}

#endif /* DNSTABLE_JSON_H */
