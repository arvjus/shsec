/* getshsec.c - SharedSecret project.

   Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include "shsec_asn1.h"
#include "config.h"
#include "defs.h"
#include "shsec.h"


#define CHECK_RES	{ if (res != ASN1_SUCCESS) { goto done; } }


/* parameters */
int verbose = 0;
static char req_type = CRT_REQUEST_KEY;
static char flags = 0;
static int lifetime = 3660;
static unsigned short key_len = 128;
static int output_format = OUTFORM_HEX;
static int fmt_margin = 0;
static char output_file[MAX_FILE_LEN], sock_file[MAX_FILE_LEN];
static char tag[MAX_TAG_LEN], peer[MAX_HOST_LEN];
static short port = DEFAULT_PORT;

static ASN1_TYPE asn1_definitions = ASN1_TYPE_EMPTY;


/* print usage */
void print_help(FILE* stream, int exit_code)
{
	fprintf(stream,
"shsec (Shared Secret Client). version %s\n"
"Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>\n\n"
"usage: %s [-hVvskdl] [-t s] [-L l] [-o f] [-F fmt] [-f m] [-S f]\n"
"       tag@peer[:port]\n"
"-h,   --help        Print this option list, then exit.\n"
"-V,   --version     Print version number, then exit.\n"
"-v,   --verbose     Be verbose. To increase level, specify twice.\n"
"-i,   --initiate    Initiate key exchange ir requested does not exist.\n"
"-s,   --store       Store key into key database on initiator's side.\n"
"-k,   --keep        Keep key in key database after key has been fetched.\n"
"-d,   --delete      Delete key from key database immeadetly.\n"
"-l,   --list        List all existing keys.\n"
"-t s, --lifetime=s  Validity in seconds for key, stored in database [3660].\n"
"-L l, --key-len=len In bits [128] or des, des2, des3, aes128, aes192, aes256.\n"
"-o f, --output=f    File to write requested key to, default is stdout.\n"
"-F f, --format=frm  Output file format, one of raw, hex, base64.\n"
"-f m, --fmt=margin  Format output to margin if output format is not binary.\n"
"-S f, --sock-file=f Path to socket file. Default is %s\n"
"tag@peer[:port]     Key tag + IP address or FQDN and optionally port.\n\n",
VERSION, PROGRAM_NAME, SOCK_FILE);
	
	exit(exit_code);
}

/* parse command line */
void get_options(int argc, char* argv[])
{
	int next_option, i;

	const char* const short_options = "hVviskdlt:L:o:F:f:S:";

	const struct option long_options[] = {
		{ "help",		0, NULL, 'h' },
		{ "version",	0, NULL, 'V' },
		{ "vebose",		0, NULL, 'v' },
		{ "initiate",	0, NULL, 'i' },
		{ "store",		0, NULL, 's' },
		{ "keep",		0, NULL, 'k' },
		{ "delete",		0, NULL, 'd' },
		{ "list",		0, NULL, 'l' },
		{ "lifetime",	1, NULL, 't' },
		{ "key-len",	1, NULL, 'L' },
		{ "output",		1, NULL, 'o' },
		{ "format",		1, NULL, 'F' },
		{ "fmt",		1, NULL, 'f' },
		{ "sock-file",	1, NULL, 'S' },
		{ NULL,			0, NULL, 0   }
	};

	const struct str_num algos[] = {
		{ "des",	56	},
		{ "des2",	112	},
		{ "des3",	168	},
		{ "aes128",	128	},
		{ "aes192",	192 },
		{ "aes256",	256	},
		{ NULL,		0	}
	};

	const struct str_num outforms[] = {
		{ "raw",	OUTFORM_RAW		},
		{ "hex",	OUTFORM_HEX		},
		{ "base64",	OUTFORM_BASE64	},
/*		{ "DER",	OUTFORM_DER		},
		{ "PEM",	OUTFORM_PEM		},
*/		{ NULL,		0				}
	};

	/* set defaults */
	strcpy(sock_file, SOCK_FILE);
	
	/* get options */
	do {
		next_option = getopt_long(argc, argv, short_options, long_options, 0);
		
		switch(next_option) {
		case 'h':
			print_help(stdout, 0);
			
		case 'V':
			fprintf(stdout, "%s %s\n", PROGRAM_NAME, VERSION);
			exit(0);
			break;

		case 'v':
			verbose ++;
			break;

		case 'i':
			flags |= FLAG_INIT_KEY;
			break;
			
		case 's':
			flags |= FLAG_STORE_KEY;
			break;
			
		case 'k':
			flags |= FLAG_KEEP_KEY;
			break;
			
		case 'd':
			req_type = CRT_DELETE_KEY;
			break;
			
		case 'l':
			req_type = CRT_ENUM_KEYS;
			break;
			
		case 't':
			lifetime = atoi(optarg);
			break;
		
		case 'L':
			if (isdigit(optarg[0])) 
				key_len = atoi(optarg);
			else {
				key_len = 0;
				for (i = 0; algos[i].str; i++) 
					if (!strcmp(algos[i].str, optarg)) {
						key_len = algos[i].num;
						break;
					}
				
				if (!key_len) 
					print_help(stderr, 1);
			}
			break;
			
		case 'o':
			if (strlen(optarg) + 1 > sizeof(output_file)) {
				print(LOG_ERR, "error: output file name is too long\n");
				exit(1);
			}
			
			strcpy(output_file, optarg);
			break;

		case 'F':
			output_format = -1;
			for (i = 0; outforms[i].str; i++) 
				if (!strcmp(outforms[i].str, optarg)) {
					output_format = outforms[i].num;
					break;
				}
			
			if (output_format == -1) 
				print_help(stderr, 1);
			break;
			
		case 'f':
			fmt_margin = atoi(optarg);
			if (fmt_margin < 4 || fmt_margin > 80) {
				print(LOG_ERR, "error: valid range for fmt margin is 4-80.\n");
				exit(1);
			}
			break;
		
		case 'S':
			if (strlen(optarg) + 1 > sizeof(sock_file)) {
				print(LOG_ERR, "error: socket file name is too long\n");
				exit(1);
			}
			
			strcpy(sock_file, optarg);
			break;

		case '?':
			print_help(stderr, 1);
		};
	} while (next_option != -1);

	/* get tag@peer[:port] */
	if (optind < argc) {
		char* at, *colon;

		if (strlen(argv[optind]) >= sizeof(tag) + sizeof(peer)) {
			print(LOG_ERR, "error: tag@peer is too long\n");
			exit(1);
		}

		at = strchr(argv[optind], '@');
		if (at && at > argv[optind]) {
			int pos = at - argv[optind];
			strncpy(tag, argv[optind], pos);
			tag[pos] = '\0';
		}
		else {
			print(LOG_ERR, "error: 'tag@' part is missing\n");
			exit(1);
		}
		
		colon = strchr(at+1, ':');
		if (colon && colon == at+1) {
			print(LOG_ERR, "error: 'peer' part is missing\n");
			exit(1);
		}
		else
		if (colon) {
			int pos = colon - at - 1;
			if (!isdigit(colon[1])) {
				print(LOG_ERR, "error: invalid peer's port value\n");
				exit(1);
			}
			
			port = atoi(&colon[1]);
			strncpy(peer, at + 1, pos);
			peer[pos] = '\0';
		}
		else
			strcpy(peer, at + 1);
	}
	else
	if (req_type != CRT_ENUM_KEYS)
		print_help(stderr, 1);
	
	/* get the rest */
	if (optind + 1 < argc) {
		print(LOG_ERR, "error: too many options\n");
		exit(1);
	}

	/* check flags */
	if (check_flag_validity(flags)) {
		print(LOG_ERR, "error: not allowed option combination\n");
		exit(1);
	}
}

/* format a ky string and output */
void format_output(FILE* output, const char* str) 
{
	int i, len;

	/* do we need to format? */
	if (!fmt_margin) {
		fprintf(output, str);
		return;
	}
	
	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (i && !(i % fmt_margin))
			fprintf(output, "\n");

		fprintf(output, "%c", str[i]);
	}

	fprintf(output, "\n");
}

/* encode_asn1_request */
void encode_asn1_request(unsigned char* buf, int* plen) 
{
	ASN1_TYPE		req = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	char			expires[20];
	unsigned char	version, tmp[2];
	time_t			timeout;

	/* convert time to string */
	time(&timeout);
	timeout += lifetime;
	time_t_to_gentime(timeout, expires);

	/* create CliReq */
	res = asn1_create_element(asn1_definitions, "SHSEC.CliReq", &req);
	CHECK_RES;
	version = CURRENT_PROTOCOL_VERSION;
	res = asn1_write_value(req, "version", &version, sizeof(version));
	CHECK_RES;

	/* fill-in values */
	switch (req_type) {
	case CRT_REQUEST_KEY:
		res = asn1_write_value(req, "reqType", "requestKey", 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.tag", tag, 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.peer", peer, 0);
		CHECK_RES;

		*((unsigned short*)tmp) = htons(port);
		res = asn1_write_value(req, "options.port", tmp, sizeof(tmp));
		CHECK_RES;
		
		*((unsigned short*)tmp) = htons(key_len);
		res = asn1_write_value(req, "options.keyLen", tmp, sizeof(tmp));
		CHECK_RES;

		res = asn1_write_value(req, "options.flags", &flags, sizeof(flags));
		CHECK_RES;

		res = asn1_write_value(req, "options.expires", expires, 0);
		CHECK_RES;
		break;

	case CRT_DELETE_KEY:
		res = asn1_write_value(req, "reqType", "deleteKey", 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.tag", tag, 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.peer", peer, 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.port", NULL, 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.keyLen", NULL, 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.flags", NULL, 0);
		CHECK_RES;

		res = asn1_write_value(req, "options.expires", NULL, 0);
		CHECK_RES;
		break;

	case CRT_ENUM_KEYS:
		res = asn1_write_value(req, "reqType", "enumKeys", 0);
		CHECK_RES;

		res = asn1_write_value(req, "options", NULL, 0);
		CHECK_RES;
		break;
	}

	/* encode whole structure */
	res = asn1_der_coding(req, "", buf, plen, NULL);
	CHECK_RES;

#ifdef DEBUG
	if (verbose > 1) {
		fprintf(stderr, "CliReq:\n");
		asn1_print_structure(stdout, req, "", ASN1_PRINT_ALL);
		fprintf(stderr, "\n");
	}
#endif
	
 done:;
	if (req != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&req);

	if (res != ASN1_SUCCESS) {
		print(LOG_ERR, "error: during request encoding %s\n",
			libtasn1_strerror(res));
		exit(1);
	}
}

/* decode_asn1_response */
void decode_asn1_response(const unsigned char* buf, int len) 
{
	ASN1_TYPE		resp = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	version, status;
	int				tag, class, version_len, status_len;

	FILE*			output = stdout;
	int				output_to_file = 0;

	/* create CliResp */
	res = asn1_create_element(asn1_definitions, "SHSEC.CliResp", &resp);
	CHECK_RES;

	/* decode whole structure */
	res = asn1_der_decoding(&resp, buf, len, NULL);
	CHECK_RES;
	if (verbose > 1) {
		fprintf(stderr, "CliResp:\n");
		asn1_print_structure(stdout, resp, "", ASN1_PRINT_ALL);
		fprintf(stderr, "\n");
	}

	/* check version */
	version_len = sizeof(version);
	res = asn1_read_value(resp, "version", &version, &version_len);
	CHECK_RES;
	if (version != CURRENT_PROTOCOL_VERSION) {
		print(LOG_ERR, "unsuported protocol version %d\n", version);
		goto done;
	}

	/* check status */
	status_len = sizeof(status);
	res = asn1_read_value(resp, "status", &status, &status_len);
	CHECK_RES;
	if (GET_ERR(status) != ERR_SUCCESS) {
		char scope[30];

		switch (GET_SCOPE(status)) {
		case SCOPE_HOST:
			strcpy(scope, "error from host");
			break;

		case SCOPE_PEER:
			strcpy(scope, "error from peer");
			break;

		default:
			strcpy(scope, "error");
			break;
		}

		print(LOG_ERR, "%s: %s. (%d)\n", scope,
			error_message(GET_ERR(status)), GET_ERR(status));
		goto done;
	}
	else
	if (req_type == CRT_DELETE_KEY)
		goto done;
	
	/* check if response type matches request */
	res = asn1_read_tag(resp, "respData", &tag, &class);
#if 0
	if (res != ASN1_SUCCESS ||
		(req_type == CRT_REQUEST_KEY && tag != ASN1_TAG_OCTET_STRING) ||
		(req_type == CRT_ENUM_KEYS && tag != ASN1_TAG_SEQUENCE)) {
		print(LOG_ERR, "error: malformed response was received\n");
		res = ASN1_SUCCESS;
		goto done;
	}
#endif	
	/* setup output */
	output_to_file = output_file[0] != '\0';
	if (output_to_file) {
		output = fopen(output_file, "wb");
		if (!output) {
			print(LOG_ERR, "error: cannot create '%s' file\n", output_file);
			goto done;
		}
	}

	/* read expected values */
	if (req_type == CRT_REQUEST_KEY) {
		unsigned char key[MAX_KEY_LEN/8];
		int	key_len;

		key_len = sizeof(key)*8;
		res = asn1_read_value(resp, "respData.key", key, &key_len);
		CHECK_RES;

		switch (output_format) {
		case OUTFORM_RAW:
			if (fwrite(key, BITS_TO_BYTES(key_len), 1, output) != 1) {
				print(LOG_ERR, "error: cannot write to '%s' file\n",
					output_file);
				goto done;
			}
			break;
		
		case OUTFORM_HEX:
			{
				int i;
				char buf[MAX_KEY_LEN/8*2], tmp[10];
				buf[0] = '\0';
				for (i = 0; i < BITS_TO_BYTES(key_len); i++) {
					sprintf(tmp, "%hhx", key[i]);
					strcat(buf, tmp);
				}

				format_output(output, buf);
			}
			break;
		
		case OUTFORM_BASE64:
			{
				char buf[MAX_KEY_LEN/8*2];
				to64frombits(buf, key, BITS_TO_BYTES(key_len));
				format_output(output, buf);
			}
			break;
		
		case OUTFORM_DER:
		case OUTFORM_PEM:
			break;
		}
	}
	else
	if (req_type == CRT_ENUM_KEYS) {
		char keyid[MAX_TAG_LEN + MAX_HOST_LEN + 1], expires[20], tmp[2];
		int num, i, len, key_len, keyid_len, expires_len;
		time_t timeout;

		res = asn1_number_of_elements(resp, "respData.keyInfo", &num);
		CHECK_RES;

		fprintf(output, "------------------------ BEGIN OF LIST "
						"--------------------------\n");
		for (i = 1; i <= num; i ++) {
			char var[50];

			sprintf(var, "respData.keyInfo.?%d.keyid", i);
			keyid_len = sizeof(keyid);
			res = asn1_read_value(resp, var, keyid, &keyid_len);
			CHECK_RES;
			keyid[keyid_len] = '\0';
			
			sprintf(var, "respData.keyInfo.?%d.keyLen", i);
			len = sizeof(tmp);
			res = asn1_read_value(resp, var, tmp, &len);
			CHECK_RES;
			key_len = ASN1_NTOHS(tmp, len);
			
			sprintf(var, "respData.keyInfo.?%d.expires", i);
			expires_len = sizeof(expires);
			res = asn1_read_value(resp, var, expires, &expires_len);
			CHECK_RES;
			expires[expires_len] = '\0';
			
			timeout = gentime_to_time_t(expires);
			if ((int)timeout != -1)
				fprintf(output, "%-20s (%3dbits), validity %s",
					keyid, key_len, ctime(&timeout));
			else
				fprintf(output, "%-20s (%3dbits), validity %s\n",
					keyid, key_len, expires);
		}
		fprintf(output, "------------------------ END OF LIST "
						"----------------------------\n");
	}

 done:;
	if (output_to_file) 
		fclose(output);

	if (resp != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&resp);

	if (res != ASN1_SUCCESS) {
		print(LOG_ERR, "error: during response decoding %s\n",
			libtasn1_strerror(res));
		exit(1);
	}
}

/* start program */
int main(int argc, char* argv[]) 
{
	int			s, rc, len, len_toreceive, len_received, len_tosend, len_sent;
	struct sockaddr_un remote;
	char		buf[1024];

	asn1_retCode	res;
		
	/* process arguments */
	output_file[0] = '\0';
	get_options(argc, argv);

#ifdef DEBUG
	print(LOG_DEBUG, "verbose: %d, flags: %0.2x, lifetime: %d, "
		"key_len: %d, output_format: %d\nfmt margin: %d, output_file: "
		"'%s', socket_file: '%s'\ntag: '%s', peer: '%s', port: %d\n",
		verbose, flags, lifetime, key_len, output_format, fmt_margin,
		output_file, sock_file, tag, peer, port);
#endif
	
	/* initialize asn definitions */
	res = asn1_array2tree(shsec_asn1_tab, &asn1_definitions, NULL);
	if (res != ASN1_SUCCESS) {
		print(LOG_ERR, "error: asn1_array2tree failed: %s\n",
			libtasn1_strerror(res));
		exit(1);
	}
	
	/* connect to socket */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	check_rc(s, "socket");
	
	remote.sun_family = AF_UNIX;
	strncpy(remote.sun_path, sock_file, sizeof(remote.sun_path) - 1);
	rc = connect(s, (struct sockaddr*)&remote, SUN_LEN(&remote));
	check_rc(rc, "connect");

	/* fill-in request */
	len = sizeof(buf);
	encode_asn1_request(buf, &len);

	/* send request */
	len_sent = 0;
	len_tosend = len;
	while (len_tosend > len_sent) {
		len = len_tosend - len_sent;
		len = send(s, &buf[len_sent], len, 0);
		check_socket(len, "send");
		len_sent += len;
	}
	
	/* receive response - we can expect at least 7 first bytes to receive */
	len = recv(s, buf, 7, 0);
	check_socket(len, "recv");
	
	len_received = len;
	len_toreceive = get_der_seq_size(buf);
	if (len_received + len_toreceive > sizeof(buf)) {
		print(LOG_ERR, "error: received package is too big\n");
		exit(1);
	}

	/* get the rest */
	while (len_toreceive > len_received) {
		len = len_toreceive - len_received;
		len = recv(s, &buf[len_received], len, 0);
		check_socket(len, "recv");
		len_received += len;
	}
	
	close(s);

	/* process response and write to output */
	decode_asn1_response(buf, len_received);

	/* deallocate resources */
	asn1_delete_structure(&asn1_definitions);

	return 0;
}

