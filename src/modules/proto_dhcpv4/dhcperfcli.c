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
static uint16_t server_port = DHCP_PORT_SERVER;
static int force_af = AF_INET; // we only do DHCPv4.


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
 *	Process command line options.
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
}

int main(int argc, char **argv)
{
	fr_debug_lvl = 4; // for now
	fr_log_fp = stdout;

	dpc_read_options(argc, argv);

	dpc_dict_init();

	dpc_event_init(autofree);

	dpc_load_input_file(autofree);

	// grab one (just because we can)
	dpc_input_t *one = dpc_get_input_list_head(&vps_list_in);
	talloc_free(one);

	return 0;
}
