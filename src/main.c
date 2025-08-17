#include <stdio.h>
#include "netinfo.h"

int main(void) {
    printf("W1: interface discovery tool\n");
    if (list_interfaces_and_print() != 0) {
        fprintf(stderr, "Error enumerating interfaces\n");
        return 1;
    }
    return 0;
}
