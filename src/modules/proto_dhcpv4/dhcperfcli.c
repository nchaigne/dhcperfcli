/*
 * dhcperfcli.c
 */

#include <freeradius-devel/libradius.h>

#undef DEBUG
#define DEBUG(fmt, ...)		if (fr_debug_lvl > 0) fr_printf_log(fmt "\n", ## __VA_ARGS__)

#undef ERROR
#define ERROR(fmt, ...)		fr_perror("ERROR: " fmt, ## __VA_ARGS__)


typedef struct dpc_input dpc_input_t;

/*
 *	Holds input data (vps read from file or stdin).
 */
struct dpc_input {
	VALUE_PAIR *vps;
};



/*
 *  Global variables.
 */
char const *radius_dir = RADDBDIR;
char const *dict_dir = DICTDIR;
fr_dict_t *dict = NULL;


/*
 *	Load input vps.
 */
static int dpc_load_input(TALLOC_CTX *ctx, FILE *file_in)
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

		// for now, just trace what we've read.
		if (fr_debug_lvl > 0) {
			DEBUG("Input vps read:");
			fr_pair_list_fprint(fr_log_fp, input->vps);
		}
		talloc_free(input);

	} while (!file_done);

	return 1;
}

/*
 *	Load dictionaries.
 */
static void dpc_dict_init()
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

int main(int argc, char **argv)
{
	fr_debug_lvl = 4; // for now
	fr_log_fp = stdout;

	dpc_dict_init();

	dpc_load_input(NULL, stdin);

	return 0;
}