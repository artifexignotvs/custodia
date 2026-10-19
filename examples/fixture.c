#include <stdio.h>
#include <string.h>

/* Exemplum innocuum: specimen tantum legitur, numquam a custode agitur. */
static const char *message = "CUSTODIA: evidence before confidence";

__attribute__((noinline)) unsigned int evidence_score(unsigned int value) {
    return (value * 7u) ^ 0x5a5au;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {
        puts(message);
        return 0;
    }
    printf("evidence score: %u\n", evidence_score((unsigned int)argc));
    return 0;
}
