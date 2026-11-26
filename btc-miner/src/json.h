#pragma once
/* Minimal JSON reader, sufficient for Stratum v1 messages. */
typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;
typedef struct jval {
    jtype t;
    int b;
    double num;
    char *str;
    int n;
    struct jval **items;
    char **keys;
} jval;

jval *json_parse(const char *s);
void json_free(jval *v);
jval *json_get(const jval *obj, const char *key); /* NULL if absent or not an object */
jval *json_at(const jval *arr, int i);            /* NULL if out of range or not an array */
const char *json_str(const jval *v);              /* NULL unless string */
