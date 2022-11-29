#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "dict.h"

#define MD5_ASCII_LENGTH 33
#define LOGFILE_NAME "file_logging.log"

void encrypt_logfile();
void decrypt_logfile();

void usage(void) {
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

void list_unauthorized_accesses(FILE *log) {

	char *line = NULL;
	size_t len = 0;
	int bytes;

	// initialize dictionary object that will store info as we parse
	dict *d = init_dict();
	if (d == NULL ){
		printf("something has gone wrong!\n");
		exit(-1);
	}

	// read log file line by line
	while ((bytes = getline(&line, &len, log)) != -1) {
		
		line[bytes-1] = '\0';	// remove the newline at the end of each line

		// split each line into its fields
		int uid 			= atoi(strtok(line, "\t\t"));
		char *filename 		= strtok(NULL, "\t\t");
		char *datetime 		= strtok(NULL, "\t\t");
		int access_type 	= atoi(strtok(NULL, "\t\t"));
		int access_denied 	= atoi(strtok(NULL, "\t\t"));
		char *fingerprint 	= strtok(NULL, "\t\t");

		// if the access was unauthorized
		if (access_denied) {

			// create entry for UID if it does not already exist
			dict_item *line_item = dict_get_item(d, uid);
			if (line_item == NULL) {	// no dict entry exists, create new one
				line_item = dict_insert(d, uid, NULL, 0);

				if (line_item == NULL) {
					printf("no more entries could be added to the dictionary!\n");
					exit(-1);
				}
			}

			// update the list of the dict entry with the filename
			dict_item_add_to_list(line_item, filename);
		}
	}

	// iterate through the dict and print
	dict_item *cur = d->head;
	for(int i=0; i<d->size; i++) {
		if (cur->counter > 7) {
			printf("%d\n", cur->uid);
		}
		cur = cur->next;
	}

	return;
}


void list_file_modifications(FILE *log, char *file_to_scan) {

	char *line = NULL;
	size_t len = 0;
	int bytes;
	char lasthash[MD5_ASCII_LENGTH] = {0};

	// initialize dictionary object that will store info as we parse
	dict *d = init_dict();
	if (d == NULL ){
		printf("something has gone wrong!\n");
		exit(-1);
	}

	// read log file line by line
	while ((bytes = getline(&line, &len, log)) != -1) {
		
		line[bytes-1] = '\0';	// remove the newline at the end of each line

		// split each line into its fields
		int uid 			= atoi(strtok(line, "\t\t"));
		char *filename 		= strtok(NULL, "\t\t");
		char *datetime 		= strtok(NULL, "\t\t");
		int access_type 	= atoi(strtok(NULL, "\t\t"));
		int access_denied 	= atoi(strtok(NULL, "\t\t"));
		char *fingerprint 	= strtok(NULL, "\t\t");

		// if the file was the file that we are looking for
		if (strcmp(filename, file_to_scan) == 0) {

			// if the file is first seen or has been modified (short-circuit to avoid segfault)
			if (strcmp(lasthash, fingerprint) != 0) {

				// create entry for UID if it does not already exist
				dict_item *line_item = dict_get_item(d, uid);
				if (line_item == NULL) {	// no dict entry exists, create new one
					line_item = dict_insert(d, uid, NULL, 0);

					if (line_item == NULL) {
						printf("no more entries could be added to the dictionary!\n");
						exit(-1);
					}
				}

				// increment the counter of the UID, indicating one more modification
				dict_item_inc_counter(line_item);
			}

			// update lasthash
			strcpy(lasthash, fingerprint);
		}
	}

	// iterate through the dict and print
	dict_item *cur = d->head;
	for(int i=0; i<d->size; i++) {
		printf("%d: %d modifications\n", cur->uid, cur->counter);
		cur = cur->next;
	}

	return;
}


int main(int argc, char *argv[]) {

	decrypt_logfile();

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen(LOGFILE_NAME, "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	encrypt_logfile();

	return 0;
}

/**
 * Encrypt the logfile with the tool from assignment 1.
 * 
 * A public.key file is both necessary and assumed to exist.
*/
void encrypt_logfile() {
	system("./rsa_assign_1 -i file_logging.log -o file_logging.log -k public.key -e");
}

/**
 * Decrypt the logfile with the tool from assignment 1.
 * 
 * A private.key file matching with the public.key file that was
 * used to encrypt is both necessary and assumed to exist.
*/
void decrypt_logfile() {
	system("./rsa_assign_1 -i file_logging.log -o file_logging.log -k private.key -d");
}
