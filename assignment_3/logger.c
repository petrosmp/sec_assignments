#define _GNU_SOURCE

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <errno.h>
#include <dlfcn.h>

#define LOGFILE_NAME "file_logging.log"
#define TMP_FILENAME "__tmpfile__"
#define CREATE_TYPE 0
#define OPEN_TYPE 1
#define WRITE_TYPE 2
#define DELETE_TYPE 3
#define DATETIME_LENGTH 26
#define BUFSIZE 1024*64
#define MD5_ASCII_LENGTH 33
#define CUSTOM_FOPS

void md2str(unsigned char *md, char *str);
void digest(FILE *f, char *str);
int access_type(const char *path, const char *mode);
void encrypt_logfile();
void decrypt_logfile();
void path2fn(const char *path, int pathlen, char *fn);


FILE *fopen(const char *path, const char *mode)  {

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	
	if (strcmp(path, "private.key") == 0 ||
		strcmp(path, "public.key") == 0  ||
		strcmp(path, LOGFILE_NAME) == 0 ||
		strcmp(path, TMP_FILENAME) == 0) 
		{
			return original_fopen_ret;
		}


	// The first time that the logger is run, decryption is not necessary
	// since the file gets created just now. In every other case, i.e.
	// if the file already exists, the file is assumed to be encrypted
	// and is decrypted, so that the rest of the entries (and not just the
	// last one) are in cleartext too, and the encryption at the end works
	// properly.
	if (access(LOGFILE_NAME, F_OK) == 0) {
		decrypt_logfile();
	}

	// get user id
	int uid = getuid();

	// get action denied flag (before hashing)
	int action_denied_flag = (original_fopen_ret == NULL && errno == 13);	// 13 -> Permission Denied

	// get the MD5 checksum of the file
	char *checksum = (char *) malloc(MD5_ASCII_LENGTH);
	memset(checksum, 0, MD5_ASCII_LENGTH);
	if (original_fopen_ret == NULL) {
		char *null_file_checksum = "Non existent file, no checksum";
		memcpy(checksum, null_file_checksum, 31);
	} else {
    	digest(original_fopen_ret, checksum);
	}

    // get date and time
    time_t *t = (time_t *) malloc(sizeof(time_t));
	memset(t, 0, sizeof(time_t));
    time(t);							// get current time
	struct tm* tm_info = localtime(t);	// convert from time_t to struct tm (needed for strftime)
	char *datetime = (char*) malloc(sizeof(char) * DATETIME_LENGTH);
	strftime(datetime, DATETIME_LENGTH, "%a %b %d %Y, %H:%M:%S", tm_info);	// format time into ASCII

	// get access type
	int acs_type = access_type(path, mode);

	// open the log file and write
	FILE *logfile = original_fopen(LOGFILE_NAME, "a");
	fprintf(
		logfile,
		"%d\t%s\t\t%s\t%d\t%d\t%s\n",
		uid, path, datetime, acs_type, action_denied_flag, checksum
	);

	// cleanup, (re-)encrypt the file and return the result of the original fopen()
	fclose(logfile);
    free(checksum);
    free(t);
	free(datetime);

	encrypt_logfile();

	return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)  {

	// have original fopen ready
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	// get file name from pointer
	char proclnk[1024];
    char path[1024];
	int fd;
    int r;
	fd = fileno(stream);						// get file descriptor
	sprintf(proclnk, "/proc/self/fd/%d", fd);	// create the path to read from
	r = readlink(proclnk, path, 1024);			// read the name from the /proc/ file system
    if (r < 0) {
        printf("failed to read link\n");		// check that reading went ok
        exit(1);
    }
    path[r] = '\0';								// NULL-terminate the string
	
	char *filename = (char*) malloc(sizeof(char) * r);
	path2fn(path, r+1, filename);				// get the filename from the full path

	// avoid infinite loop
	if (strcmp(filename, "private.key") == 0 ||
		strcmp(filename, "public.key" ) == 0 ||
		strcmp(filename,  LOGFILE_NAME) == 0 ||
		strcmp(filename,  TMP_FILENAME) == 0) 
		{
			return original_fwrite_ret;
		}

	// decrypt if needed (check fopen for more on this)
	if (access(LOGFILE_NAME, F_OK) == 0) {
		decrypt_logfile();
	}

	// get user id
	int uid = getuid();

	// get action denied flag (before hashing)
	int action_denied_flag = (original_fwrite_ret == -1 && errno == 13) || (original_fwrite_ret==0 && nmemb!=0);	// 13 -> Permission Denied

	fflush(stream); // flush the stream to force it to write, so the digest includes the newly written data

	// get the MD5 checksum of the file
	char *checksum = (char *) malloc(MD5_ASCII_LENGTH);
	memset(checksum, 0, MD5_ASCII_LENGTH);
	digest(stream, checksum);

    // get date and time
    time_t *t = (time_t *) malloc(sizeof(time_t));
	memset(t, 0, sizeof(time_t));
    time(t);							// get current time
	struct tm* tm_info = localtime(t);	// convert from time_t to struct tm (needed for strftime)
	char *datetime = (char*) malloc(sizeof(char) * DATETIME_LENGTH);
	strftime(datetime, DATETIME_LENGTH, "%a %b %d %Y, %H:%M:%S", tm_info);	// format time into ASCII

	// access type is always write in fwrite()
	int acs_type = WRITE_TYPE;

	// open the log file and write
	FILE *logfile = original_fopen(LOGFILE_NAME, "a");
	fprintf(
		logfile,
		"%d\t%s\t\t%s\t%d\t%d\t%s\n",
		uid, filename, datetime, acs_type, action_denied_flag, checksum
	);

	fclose(logfile);
	free(checksum);
    free(t);
	free(datetime);
	free(filename);

	encrypt_logfile();

	return original_fwrite_ret;
}

/**
 * Given a path to a file and a mode of access return the access
 * type (access types are defined in the start of this file).
*/
int access_type(const char *path, const char *mode) {

	if (access(path, F_OK) != 0) {	// if the file does not exist
		if (mode[0] == 'r') {
			return OPEN_TYPE;	// access is not denied but the file cannot be opened, just return the desired access type
		}
		return CREATE_TYPE;		// both a and w create if not exists, r+ does not
	}

	// we reach here if file exists
	if (mode[0] == 'w') {
		return DELETE_TYPE;		// overwrite counts as deletion
	}

	return OPEN_TYPE;			// WRITE_TYPE is only logged by fwrite, everything else is OPEN_TYPE
}

/**
 * Calculate the MD5 checksum of the file with the given name
 * and store it as ASCII in str.
 * 
 * str is assumed to be of right size (MD5_ASCII_LENGTH or 33)
 * and f is assumed to not be null.
 * 
 * This function uses OpenSSL's MD5_Init, MD5_Update and 
 * MD5_Final routines, the use of which is advised against by
 * OpenSSL.
*/
void digest(FILE *f, char *str) {
    MD5_CTX c;
    unsigned char md[MD5_DIGEST_LENGTH];
    int fd;
    int i;
    static unsigned char buf[BUFSIZE] = {0};

    MD5_Init(&c);						// initialize md5 object
    fd = fileno(f);						// get the file descriptor of the stream so read() cna be used
	lseek(fd, (off_t) 0, SEEK_SET);		// seek to the start of the file

    // iterate through the file block by block and hash it
    for (;;) {
        i = read(fd, buf, BUFSIZE);             // use the read() syscall instead of fread()
        if (i <= 0) break;                      // stop at error (<) or EOF (=)
		MD5_Update(&c, buf, (unsigned long)i);  // update the hash with the (hash of the) new block
    }

    // store the hash in md and clean up the md5 object
    MD5_Final(&(md[0]),&c);

    // convert the hash to ASCII and store it in str
    md2str(md, str);
}

/**
 * Converts an MD5 digest to ASCII from bytes.
*/
void md2str(unsigned char *md, char *result) {

    char str[3] = {0};

    // iterate through the digest and put hex values in result as ASCII
    for (int i=0; i<MD5_DIGEST_LENGTH; i++){
        sprintf(str, "%02x",md[i]);
        strcat(result, str);
    }

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

/**
 * Convert a path to a filename (keep the part after the last /).
*/
void path2fn(const char *path, int pathlen, char *fn) {
	int last_slash_index = -1;
	for (int i=pathlen-1; i>=0; i--) {
		if (path[i] == '/') {
			last_slash_index = i;
			break;
		}
	}

	for(int j=0; j<pathlen-last_slash_index-1; j++) {
		fn[j] = path[last_slash_index+j+1];
	}

	fn[pathlen-last_slash_index-1] = '\0';

}
