#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dict.h"


int main() {

    list_demo();
    dict_demo();

}



void dict_demo() {
    
    dict *d = init_dict();
    dict_item *a = dict_insert(d, 1000, NULL, 0);
    char c1[] = "bogus_filename.foo";
    
    printf("\n==================================\n");
    dict_item_add_to_list(a, c1);
    printf("The dictionary has %d element(s).\n", d->size);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);
    print_list(a->list, MAX_FILES);


    printf("\n==================================\n");
    char c2[] = "blibliblo.txt";
    dict_item_add_to_list(a, c2);
    printf("The dictionary has %d element(s).\n", d->size);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);
    print_list(a->list, MAX_FILES);


    printf("\n==================================\n");
    // already present element
    char c3[] = "bogus_filename.foo";
    dict_item_add_to_list(a, c3);
    printf("The dictionary has %d element(s).\n", d->size);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);
    print_list(a->list, MAX_FILES);


    // repeat above process for new element
    printf("\n========== NEW ELEMENT ==========\n");
    a = dict_insert(d, 2000, NULL, 0);
    printf("\n==================================\n");
    dict_item_add_to_list(a, c1);
    printf("The dictionary has %d element(s).\n", d->size);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);
    print_list(a->list, MAX_FILES);
    printf("\n==================================\n");
    dict_item_add_to_list(a, c2);
    printf("The dictionary has %d element(s).\n", d->size);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);
    print_list(a->list, MAX_FILES);
    printf("\n==================================\n");
    dict_item_add_to_list(a, c3);
    printf("The dictionary has %d element(s).\n", d->size);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);
    print_list(a->list, MAX_FILES);


    printf("\n========== INCREMENT COUNTER ==========\n");
    dict_item_inc_counter(a);
    printf("%d's list has %d unique filenames:\n",a->uid, a->counter);


    printf("\n========== SEARCH IN DICT ==========\n");
    // find element
    a = dict_get_item(d, 1000);
    if (a!= NULL) {
        printf("found element a: {uid: %d, counter: %d, next: %p}\n", a->uid, a->counter, a->next);
    }

    printf("\n========== FREE DICT ==========\n");
    int fd = free_dict(d);
    printf("freed %d items from dict\n", fd);
}

int dict_item_add_to_list(dict_item *item, char *str) {

    // if the str is already in the item's list, don't do anything
    if (find_in_list(item->list, MAX_FILES, str) == 1) {
        return 1;
    }

    add_str_to_list(str, item->list, item->counter);
    item->counter++;

    return 0;
}

void dict_item_inc_counter(dict_item *item) {
    item->counter++;
}

dict *init_dict() {

    // allocate memory for the new dict
    dict *new_dict = (dict *) malloc(sizeof(dict));
    if (new_dict == NULL) {
        printf("no memory left for new dictionary\n");
        return NULL;
    }

    // initialize the fields of the new dict
    new_dict->size = 0;
    new_dict->head = NULL;
    new_dict->last = NULL;

    return new_dict;
}

int free_dict(dict *d) {

    // free all the items of the dict
    int i;
    dict_item *cur = d->head;
    for(i=0; i<d->size; i++) {
        

        if (cur == NULL) {
            printf("something has probably gone wrong.\n");
            break;
        }

        dict_item *tmp = cur->next;

        free_list(cur->list, MAX_FILES);

        free(cur);
        cur = tmp;

    }

    // free the dict
    free(d);

    return i;   // the number of items freed
}

dict_item *dict_insert(dict *d, int UID, char **list, int counter) {

    // create the new item
    dict_item *new_item = (dict_item *) malloc(sizeof(dict_item));
    if (new_item == NULL) {
        printf("there is no memory for more dictionary items\n");
        return NULL;
    }

    new_item->uid = UID;
    new_item->counter = counter;

    if (d->head == NULL) {  // empty dict case
        d->head = new_item;
        d->last = new_item;
    } else {
        d->last->next = new_item;
        d->last = new_item;
    }

    d->size++;

    return new_item;
}

dict_item *dict_get_item(dict *d, int UID) {

    dict_item *cur = d->head;

    for(int i=0; i<d->size; i++) {
        if (cur->uid == UID) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

void list_demo() {

    int uids[] = {1000, 0, 3000, 400, 4, 50};

    char *list[MAX_USERS];

    // add ints to list
    for(int i=0; i<6; i++) {
        add_int_to_list(uids[i], list, i);
    }

    // add str to list
    char c1[] = "hello there general kenobi";
    add_str_to_list(c1, list, 6);

    print_list(list, MAX_USERS);

    // search in list
    printf("%d is %sin the list\n", 1000, find_in_list(list, MAX_USERS,"1000") ? "" : "not ");
    printf("%d is %sin the list\n", 999, find_in_list(list, MAX_USERS,"999") ? "" : "not ");

    // free list
    int f = free_list(list, MAX_USERS);
    printf("freed %d elements\n", f);
}

int add_int_to_list(int n, char **list, int index) {

    // allocate and clear memory for new list element
    list[index] = (char *) malloc(MAX_FILENAME_LENGTH);
    memset(list[index], 0, MAX_FILENAME_LENGTH);

    // allocate and clear a string to put the int into
    char *c = (char *) malloc(MAX_FILENAME_LENGTH);

    if (c == NULL) {    // malloc failed
        printf("there is no more memory that can be allocated!\n");
        return -1;
    }

    memset(c, 0, MAX_FILENAME_LENGTH);

    // put the int in the string
    sprintf(c, "%d", n);

    // copy the string into the list
    memcpy(list[index], c, strlen(c));

    // free the string
    free(c);

    return 0;
}

void add_str_to_list(char *str, char **list, int index) {

    // allocate and clear memory for new list element
    list[index] = (char *) malloc(MAX_FILENAME_LENGTH);
    memset(list[index], 0, MAX_FILENAME_LENGTH);

    memcpy(list[index], str, strlen(str));
}

int free_list(char **list, int maxsize) {
    int i;
    for (i=0; i<maxsize; i++) {
        if (list[i] == NULL) {
            break;
        }
        free(list[i]);
    }
    return i;
}

void print_list(char **list, int maxsize) {
    for (int i=0; i<maxsize; i++) {
        if (list[i] == NULL) {
            break;
        }
        printf("list[%d]: %s\n", i, list[i]);
    }
}

int find_in_list(char **list, int maxsize, char *des) {

    for(int i=0; i<maxsize; i++) {
        if (list[i] == NULL) {
            return 0;
        }
        if (strcmp(list[i], des) == 0) {
            return 1;
        }
    }

    return 0;
}
