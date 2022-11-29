#define MAX_FILENAME_LENGTH 100
#define MAX_USERS 1000
#define MAX_FILES 10000

/**
 * An item of the dictionary

 * Functions offered:
 *  - dict_item_add_to_list()
 *  - dict_item_inc_counter()
*/
typedef struct dict_entry {
    int uid;                    /** the UID that this entry is about */
    char *list[MAX_FILES];      /** the list of (unique) filenames that UID accessed */
    int counter;                /** the number of (unique) files that UID accessed */
    struct dict_entry *next;    /** next item in the dict */
} dict_item;

/**
 * A key-value structure. Keys are UID's values are
 * filename lists and counters.
 * 
 * Basically just a linked list of items.
 * 
 * Functions offered:
 *  - init_dict()
 *  - dict_insert()
 *  - dict_get_item() 
 *  - free_dict()
*/
typedef struct dictionary {
    struct dict_entry *head; /** the head of the dictionary */
    struct dict_entry *last; /** the last item of the dictionary*/
    int size;        /** the number of entries in the dictionary */
} dict;

/**
 * Convert n to string and add it to list at index.
 * 
 * list[index] is allocated in this function.
*/
int add_int_to_list(int n, char **list, int index);

/**
 * Free the given list of up to maxsize elements.
 * 
 * Returns the number of elements freed.
*/
int free_list(char **list, int maxsize);

/**
 * Print up to maxsize elements of list.
*/
void print_list(char **list, int maxsize);

/**
 * Copy the contents of str to list[index].
*/
void add_str_to_list(char *str, char **list, int index);

/**
 * Search for des in up to maxsize elements of list
 * 
 * Returns 1 if the element is found, 0 otherwise.
*/
int find_in_list(char **list, int maxsize, char *des);

/**
 * Initialize a new dict structure.
 * 
 * Returns NULL on failure.
*/
dict *init_dict();

/**
 * Free all the items of a dict and then the dict itself.
 * 
 * Returns the number of items freed.
*/
int free_dict(dict *d);

/**
 * Insert a new item in the dictionary.
 * 
 * Returns a pointer to the new item on success, NULL on failure.
*/
dict_item *dict_insert(dict *d, int UID, char **list, int counter);

/**
 * Serially search the dictionary for an item with the given UID.
 * 
 * Returns a dict_item* on success, NULL on failure.
 * 
*/
dict_item *dict_get_item(dict *d, int UID);

/**
 * Add str to the item's list. If it is already there it is
 * not added.
 * 
 * Returns 1 is the str is already in the list, 0 if it just
 * got added.
*/
int dict_item_add_to_list(dict_item *item, char *str);

/**
 * Increment item's counter (by one).
 * 
 * item is assumed to not be NULL;
*/
void dict_item_inc_counter(dict_item *item);

/**
 * Demonstrate the use of the list.
*/
void list_demo();

/**
 * Demonstrate the use of a dict.
*/
void dict_demo();
