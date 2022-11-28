#define _GNU_SOURCE

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>

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
void digest(const char *filename, char *str);
int access_type(const char *path, const char *mode);
void encrypt_logfile();
void decrypt_logfile();


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
	char *checksum = (char *) malloc(sizeof(char) * MD5_ASCII_LENGTH);
    digest(path, checksum);

    // get date and time
    time_t *t = (time_t *) malloc(sizeof(time_t));
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


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


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
void digest(const char *filename, char *str) {
    MD5_CTX c;
    unsigned char md[MD5_DIGEST_LENGTH];
    int fd;
    int i;
    static unsigned char buf[BUFSIZE];
    
    MD5_Init(&c);   // initialize md5 object
    fd = open(filename, O_RDONLY); // get the file descriptor (and not a file pointer) so read() can be used
    
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
