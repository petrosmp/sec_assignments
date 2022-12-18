#define _GNU_SOURCE

#include <pcap/pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define LIVE_CAPTURE 1
#define READ_FROM_FILE 2
#define MAX_FILTER_LENGTH 1024
#define MAX_FILENAME_LENGTH 1024
#define TRUE  1
#define FALSE 0

void usage();

/**
 * Print the help message
*/
void usage() {
	printf(
	    "\n"
	    "usage:\n"
	    "\t./pcap_ex \n"
		"Options:\n"
		"-i <interface>, Network interface name (e.g., eth0)\n"
		"-r <filename>, Packet capture file name (e.g., test.pcap)\n"
		"-f <filter>, Filter expression (e.g., port 8080)\n"
		"-h, Help message\n\n"
	);

	exit(1);
}

/**
 * Capture packets live from an interface
*/
void live_capture(char *interface) {

}


int main(int argc, char* argv[]) {
    
	// prepare to parse the arguments
	int mode = -1;										// should not be -1 after parsing, would mean that no option was given and help was not printed
	char *arg = (char *) malloc(MAX_FILENAME_LENGTH);	// allocate space for the argument (interface or file)
	memset(arg, 0, MAX_FILENAME_LENGTH);				// zerofill the argument to avoid errors
	char *filter = NULL;

    // parse the arguments
    char ch;
    while ((ch = getopt(argc, argv, "hi:r:f:")) != -1) {
		switch (ch) {		
			case 'i':
				mode = LIVE_CAPTURE;
				memcpy(arg, optarg, strlen(optarg));	// assuming that interface names are small and will not cause overflows :)
				break;
			case 'r':
				mode = READ_FROM_FILE;

				// filenames/paths can be long, better safe than sorry
				if (strlen(optarg) > MAX_FILENAME_LENGTH) {
					printf("Max filename limit exceeded!\n");
					exit(-1);
				}
				memcpy(arg, optarg, strlen(optarg));
				break;
			case 'f':
				filter = (char *) malloc(strlen(optarg));	// allocate space for the filter
				memset(filter, 0, strlen(optarg));			// zerofill the filter to avoid errors (overkill)
				memcpy(filter, optarg, strlen(optarg));
				break;
			default:
				// print help
				usage();
		}
	}

	// we should have a mode specified and know whether we have a filter or not by now
	if (mode == READ_FROM_FILE) {
		printf("Mode is read from file: %s", arg);
		if (filter != NULL) {
			printf(" and filter expression is %s\n", filter);
		} else {
			printf("\n");
		}
	} else if (mode == LIVE_CAPTURE) {
		printf("Mode is live capture on interface %s", arg);
		if (filter != NULL) {
			printf(" and filter expression is %s\n", filter);
		} else {
			printf("\n");
		}
	}




	// cleanup
	free(arg);
	if (filter != NULL) {
		free(filter);
	}

}
