#include "json.h"
#include <stdlib.h>
#include <string.h>

typedef struct { const char *p; int depth; } P;

static void ws(P *p) { while (*p->p == ' ' || *p->p == '\t' || *p->p == '\n' || *p->p == '\r') p->p++; }
static jval *mk(jtype t) { jval *v = calloc(1, sizeof *v); if (v) v->t = t; return v; }
static jval *val(P *p);

static char *str(P *p) {
    if (*p->p != '"') return NULL;
    p->p++;
    size_t cap = 32, n = 0;
    char *s = malloc(cap);
    if (!s) return NULL;
    while (*p->p && *p->p != '"') {
        char c = *p->p++;
        if (c == '\\') {
            char e = *p->p++;
            switch (e) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'u': {
                unsigned u = 0;
                for (int i = 0; i < 4; i++) {
                    char h = *p->p;
                    if (!h) { free(s); return NULL; }
                    p->p++;
                    u = u * 16 + (unsigned)(h >= 'a' ? h - 'a' + 10 : h >= 'A' ? h - 'A' + 10 : h - '0');
                }
                c = u < 128 ? (char)u : '?';
                break;
            }
            case 0: free(s); return NULL;
            default: c = e;
            }
        }
        if (n + 2 > cap) { cap *= 2; char *t = realloc(s, cap); if (!t) { free(s); return NULL; } s = t; }
        s[n++] = c;
    }
    if (*p->p != '"') { free(s); return NULL; }
    p->p++;
    s[n] = 0;
    return s;
}

static int push(jval *v, jval *item, char *key) {
    jval **ni = realloc(v->items, sizeof(jval *) * (v->n + 1));
    if (!ni) return 0;
    v->items = ni;
    if (v->t == J_OBJ) {
        char **nk = realloc(v->keys, sizeof(char *) * (v->n + 1));
        if (!nk) return 0;
        v->keys = nk;
        v->keys[v->n] = key;
    }
    v->items[v->n++] = item;
    return 1;
}

static jval *val(P *p) {
    ws(p);
    if (++p->depth > 64) return NULL;
    jval *v = NULL;
    char c = *p->p;
    if (c == '{' || c == '[') {
        int obj = c == '{';
        v = mk(obj ? J_OBJ : J_ARR);
        if (!v) goto out;
        p->p++;
        ws(p);
        if (*p->p == (obj ? '}' : ']')) { p->p++; goto out; }
        for (;;) {
            char *key = NULL;
            if (obj) {
                ws(p);
                key = str(p);
                ws(p);
                if (!key || *p->p != ':') { free(key); goto fail; }
                p->p++;
            }
            jval *it = val(p);
            if (!it || !push(v, it, key)) { json_free(it); free(key); goto fail; }
            ws(p);
            if (*p->p == ',') { p->p++; continue; }
            if (*p->p == (obj ? '}' : ']')) { p->p++; break; }
            goto fail;
        }
    } else if (c == '"') {
        v = mk(J_STR);
        if (v && !(v->str = str(p))) goto fail;
    } else if (!strncmp(p->p, "true", 4)) { v = mk(J_BOOL); if (v) v->b = 1; p->p += 4; }
    else if (!strncmp(p->p, "false", 5)) { v = mk(J_BOOL); p->p += 5; }
    else if (!strncmp(p->p, "null", 4)) { v = mk(J_NULL); p->p += 4; }
    else {
        char *end;
        double d = strtod(p->p, &end);
        if (end == p->p) goto out;
        v = mk(J_NUM);
        if (v) v->num = d;
        p->p = end;
    }
out:
    p->depth--;
    return v;
fail:
    json_free(v);
    p->depth--;
    return NULL;
}

jval *json_parse(const char *s) { P p = {s, 0}; return val(&p); }

void json_free(jval *v) {
    if (!v) return;
    for (int i = 0; i < v->n; i++) { json_free(v->items[i]); if (v->keys) free(v->keys[i]); }
    free(v->items); free(v->keys); free(v->str); free(v);
}

jval *json_get(const jval *o, const char *k) {
    if (!o || o->t != J_OBJ) return NULL;
    for (int i = 0; i < o->n; i++) if (!strcmp(o->keys[i], k)) return o->items[i];
    return NULL;
}
jval *json_at(const jval *a, int i) { return (a && a->t == J_ARR && i >= 0 && i < a->n) ? a->items[i] : NULL; }
const char *json_str(const jval *v) { return (v && v->t == J_STR) ? v->str : NULL; }
