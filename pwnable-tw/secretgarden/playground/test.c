#include <stdlib.h>

int main() {
    long* p = malloc(4);
    long* t = malloc(4);
    free(p);
    free(t);
    free(p);
    p = malloc(4);
    *p = &system + 0x380418;
    malloc(4);
    malloc(4);
    malloc(4);
    return 0;
}