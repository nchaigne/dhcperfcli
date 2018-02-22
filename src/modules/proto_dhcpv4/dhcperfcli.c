/*
 * dhcperfcli.c
 */

#include "dhcperfcli.h"


/*
 *	Global variables.
 */
char const *radius_dir = RADDBDIR;
char const *dict_dir = DICTDIR;
fr_dict_t *dict = NULL;

TALLOC_CTX *autofree = NULL;
fr_event_list_t *event_list = NULL;

static char const *file_vps_in = NULL;
static dpc_input_list_t vps_list_in = { 0 };

static fr_ipaddr_t server_ipaddr = { 0 };
static fr_ipaddr_t client_ipaddr = { 0 };
static uint16_t server_port = DHCP_PORT_SERVER;
static int force_af = AF_INET; // we only do DHCPv4.
static int packet_code = 0;

/*
 *	Static functions declaration.
 */
static dpc_input_t *dpc_get_input_list_head(dpc_input_list_t *list);
static VALUE_PAIR *dpc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);


/*
 *	Basic send / receive, for now.
 */
static int sockfd;
static struct timeval tv_timeout;
static int send_with_socket(RADIUS_PACKET **reply, RADIUS_PACKET *request)
{
	int on = 1;

	sockfd = fr_socket_server_udp(&request->src_ipaddr, &request->src_port, NULL, false);
	if (sockfd < 0) {
		ERROR("Error opening socket: %s", fr_strerror());
		return -1;
	}

	if (fr_socket_bind(sockfd, &request->src_ipaddr, &request->src_port, NULL) < 0) {
		ERROR("Error binding socket: %s", fr_strerror());
		return -1;
	}

	/*
	 *	Set option 'receive timeout' on socket.
	 *	Note: in case of a timeout, the error will be "Resource temporarily unavailable".
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_timeout, sizeof(struct timeval)) == -1) {
		ERROR("Failed setting socket timeout: %s", fr_syserror(errno));
		return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		ERROR("Can't set broadcast option: %s", fr_syserror(errno));
		return -1;
	}
	request->sockfd = sockfd;

	if (fr_dhcpv4_udp_packet_send(request) < 0) {
		ERROR("Failed sending: %s", fr_syserror(errno));
		return -1;
	}

	*reply = fr_dhcpv4_udp_packet_recv(sockfd);
	if (!*reply) {
		if (errno == EAGAIN) {
			fr_strerror(); /* clear error */
			ERROR("Timed out waiting for reply");
		} else {
			ERROR("Error receiving reply");
		}
		return -1;
	}

	return 0;
}

static RADIUS_PACKET *request_init(dpc_input_t *input)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	RADIUS_PACKET *request;

	MEM(request = fr_radius_alloc(input, true));

	// fill in the packet value pairs
	dpc_pair_list_append(request, &request->vps, input->vps);

	/*
	 *	Fix / set various options
	 */
	for (vp = fr_pair_cursor_init(&cursor, &input->vps);
	     vp;
	     vp = fr_pair_cursor_next(&cursor)) {
		/*
		 *	Allow to set packet type using DHCP-Message-Type
		 */
		if (vp->da->vendor == DHCP_MAGIC_VENDOR && vp->da->attr == FR_DHCPV4_MESSAGE_TYPE) {
			request->code = vp->vp_uint32 + FR_DHCPV4_OFFSET;
		} else if (!vp->da->vendor) switch (vp->da->attr) {
		/*
		 *	Allow it to set the packet type in
		 *	the attributes read from the file.
		 *	(this takes precedence over the command argument.)
		 */
		case FR_PACKET_TYPE:
			request->code = vp->vp_uint32;
			break;

		case FR_PACKET_DST_PORT:
			request->dst_port = vp->vp_uint16;
			break;

		case FR_PACKET_DST_IP_ADDRESS:
		case FR_PACKET_DST_IPV6_ADDRESS:
			memcpy(&request->dst_ipaddr, &vp->vp_ip, sizeof(request->src_ipaddr));
			break;

		case FR_PACKET_SRC_PORT:
			request->src_port = vp->vp_uint16;
			break;

		case FR_PACKET_SRC_IP_ADDRESS:
		case FR_PACKET_SRC_IPV6_ADDRESS:
			memcpy(&request->src_ipaddr, &vp->vp_ip, sizeof(request->src_ipaddr));
			break;

		default:
			break;
		} /* switch over the attribute */

	} /* loop over the input vps */

	/*
	 *	Set defaults if they weren't specified via pairs
	 */
	if (request->src_port == 0) request->src_port = server_port + 1;
	if (request->dst_port == 0) request->dst_port = server_port;
	if (request->src_ipaddr.af == AF_UNSPEC) request->src_ipaddr = client_ipaddr;
	if (request->dst_ipaddr.af == AF_UNSPEC) request->dst_ipaddr = server_ipaddr;
	if (!request->code) request->code = packet_code;
	
	return request;
}

static void dpc_do_request(void)
{
	RADIUS_PACKET *request = NULL;
	RADIUS_PACKET *reply = NULL;
	int ret;

	// grab one input entry
	dpc_input_t *input = dpc_get_input_list_head(&vps_list_in);

	request = request_init(input);

	if (fr_debug_lvl > 1) {
		DEBUG2("Request input vps:");
		fr_pair_list_fprint(fr_log_fp, request->vps);
	}

	/*
	 *	Encode the packet
	 */
	if (fr_dhcpv4_packet_encode(request) < 0) {
		ERROR("Failed encoding packet");
		exit(EXIT_FAILURE);
	}

	//if (fr_debug_lvl) {
	//	fr_dhcpv4_packet_decode(request);
	//	dhcp_packet_debug(request, false);
	//}

	ret = send_with_socket(&reply, request);

	if (reply) {
		if (fr_dhcpv4_packet_decode(reply) < 0) {
			ERROR("Failed decoding packet");
			ret = -1;
		}
		//dhcp_packet_debug(reply, true);
	}

	talloc_free(input);
}

/*
 *	Append a list of VP. (inspired from FreeRADIUS's fr_pair_list_copy.)
 */
static VALUE_PAIR *dpc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from)
{
	vp_cursor_t src, dst;

	if (NULL == *to) { // fall back to fr_pair_list_copy for a new list.
		*to = fr_pair_list_copy(ctx, from);
		return (*to);
	}

	VALUE_PAIR *out = *to, *vp;

	fr_pair_cursor_init(&dst, &out);
	for (vp = fr_pair_cursor_init(&src, &from);
	     vp;
	     vp = fr_pair_cursor_next(&src)) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&out);
			return NULL;
		}
		fr_pair_cursor_append(&dst, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	return *to;
}

/*
 *	Add an allocated input entry to the tail of the list.
 */
static void dpc_add_input_entry(dpc_input_list_t *list, dpc_input_t *entry)
{
	if (!list || !entry) return;

	if (!list->head) {
		assert(list->tail == NULL);
		list->head = entry;
		entry->prev = NULL;
	} else {
		assert(list->tail != NULL);
		assert(list->tail->next == NULL);
		list->tail->next = entry;
		entry->prev = list->tail;
	}
	list->tail = entry;
	entry->next = NULL;
	entry->list = list;
	list->size ++;
}

/*
 *	Remove an input entry from its list.
 */
static dpc_input_t *dpc_yank_input_entry(dpc_input_t *entry)
{
	if (!entry) return NULL; // should not happen.
	if (!entry->list) return entry; // not in a list: just return the entry.

	dpc_input_t *prev, *next;

	prev = entry->prev;
	next = entry->next;

	dpc_input_list_t *list = entry->list;

	assert(list->head != NULL); // entry belongs to a list, so the list can't be empty.
	assert(list->tail != NULL); // same.

	if (prev) {
		assert(list->head != entry); // if entry has a prev, then entry can't be head.
		prev->next = next;
	}
	else {
		assert(list->head == entry); // if entry has no prev, then entry must be head.
		list->head = next;
	}

	if (next) {
		assert(list->tail != entry); // if entry has a next, then entry can't be tail.
		next->prev = prev;
	}
	else {
		assert(list->tail == entry); // if entry has no next, then entry must be tail.
		list->tail = prev;
	}

	entry->list = NULL;
	entry->prev = NULL;
	entry->next = NULL;
	list->size --;
	return entry;
}

/*
 *	Get the head input entry from a list.
 */
static dpc_input_t *dpc_get_input_list_head(dpc_input_list_t *list)
{
	if (!list) return NULL;
	if (!list->head || list->size == 0) { // list is empty.
		return NULL;
	}
	// list is valid and has at least one element.
	return dpc_yank_input_entry(list->head);
}

/*
 *	Handle a list of input vps we've just read.
 */
static void dpc_handle_input(dpc_input_t *input)
{
	// for now, just trace what we've read.
	if (fr_debug_lvl > 1) {
		DEBUG2("Input vps read:");
		fr_pair_list_fprint(fr_log_fp, input->vps);
	}

	dpc_add_input_entry(&vps_list_in, input);
}

/*
 *	Load input vps.
 */
static void dpc_load_input(TALLOC_CTX *ctx, FILE *file_in)
{
	bool file_done = false;
	dpc_input_t *input;

	/*
	 *	Loop until the file is done.
	 */
	do {
		MEM(input = talloc_zero(ctx, dpc_input_t));

		if (fr_pair_list_afrom_file(input, &input->vps, file_in, &file_done) < 0) {
			ERROR("Error parsing input vps");
			talloc_free(input);
			break;
		}
		if (NULL == input->vps) {
			/* Last line might be empty, in this case readvp2 will return a NULL vps pointer. Silently ignore this. */
			talloc_free(input);
			break;
		}

		dpc_handle_input(input);

	} while (!file_done);

	DEBUG("Done reading input, list size: %d", vps_list_in.size);
}

/*
 *	Load input vps, either from a file if specified, or stdin otherwise.
 */
static int dpc_load_input_file(TALLOC_CTX *ctx)
{
	FILE *file_in = NULL;

	/*
	 *	Determine where to read the vps from.
	 */
	if (file_vps_in && strcmp(file_vps_in, "-") != 0) {
		DEBUG("Opening input file: %s", file_vps_in);

		file_in = fopen(file_vps_in, "r");
		if (!file_in) {
			ERROR("Error opening %s: %s", file_vps_in, strerror(errno));
			return -1;
		}
	} else {
		DEBUG("Reading input vps from stdin");
		file_in = stdin;
	}

	dpc_load_input(ctx, file_in);

	if (file_in != stdin) fclose(file_in);
	return 0;
}

/*
 *	Load dictionaries.
 */
static void dpc_dict_init(void)
{
	fr_dict_attr_t const *da;

	DEBUG("Including dictionary file \"%s/%s\"", dict_dir, FR_DICTIONARY_FILE);
	if (fr_dict_from_file(NULL, &dict, dict_dir, FR_DICTIONARY_FILE, "dhcperfcli") < 0) {
		fr_perror("dhcperfcli");
		exit(EXIT_FAILURE);
	}

	DEBUG("Including dictionary file \"%s/%s\"", radius_dir, FR_DICTIONARY_FILE);
	if (fr_dict_read(dict, radius_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, "Failed to initialize the dictionaries");
		exit(EXIT_FAILURE);
	}
	fr_strerror(); /* Clear the error buffer */

	/*
	 *	Ensure that dictionary.dhcp is loaded.
	 */
	da = fr_dict_attr_by_name(NULL, "DHCP-Message-Type");
	if (!da) {
		if (fr_dict_read(dict, dict_dir, "dictionary.dhcp") < 0) {
			ERROR("Failed reading dictionary.dhcp");
			exit(EXIT_FAILURE);
		}
	}
}

/*
 *	Initialize event list.
 */
static void dpc_event_init(TALLOC_CTX *ctx)
{
	event_list = fr_event_list_alloc(ctx, NULL, NULL);
	if (!event_list) {
		ERROR("Failed to create event list");
		exit(EXIT_FAILURE);
	}
}

/*
 *	Resolve host address.
 */
static void dpc_resolve_hostaddr(char *host_arg, fr_ipaddr_t *host_ipaddr, uint16_t *host_port)
{
	if (!host_arg || !host_ipaddr || !host_port) return;

	uint16_t port;

	if (fr_inet_pton_port(host_ipaddr, &port, host_arg, -1, force_af, true, true) < 0) {
		ERROR("Failed to parse host address");
		exit(EXIT_FAILURE);
	}

	if (port != 0) { /* If a port is specified, use it. Otherwise, keep default. */
		*host_port = port;
	}
}

/*
 *	Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status?stderr:stdout;

	fprintf(output, "Usage placeholder\n");

	exit(status);
}

/*
 *	Process command line options and arguments.
 */
static void dpc_read_options(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "f:")) != EOF) switch (c) {
		case 'f':
			file_vps_in = optarg;
			break;

		default:
			usage(1);
			break;
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (argc - 1 < 1) usage(1);

	/*
	 *	Resolve server host address and port.
	 */
	dpc_resolve_hostaddr(argv[1], &server_ipaddr, &server_port);
	client_ipaddr.af = server_ipaddr.af;
}

int main(int argc, char **argv)
{
	fr_debug_lvl = 4; // for now
	fr_log_fp = stdout;

	dpc_read_options(argc, argv);

	dpc_dict_init();

	dpc_event_init(autofree);

	dpc_load_input_file(autofree);

	// for now, just send one
	packet_code = FR_DHCPV4_DISCOVER;
	dpc_do_request();

	return 0;
}
