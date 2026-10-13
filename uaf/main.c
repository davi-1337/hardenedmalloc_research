#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    char flag[64];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) { printf("Create a local 'flag.txt' file.\n"); exit(1); }
    fgets(flag, 64, f);
    printf("FLAG: %s\n", flag);
}

void menu() {
    printf("\n1. Allocate\n2. Free\n3. Print\n4. Edit\nChoice: ");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    void *chunks[10] = {0};
    int choice, idx, size;

    while(1) {
        menu();
        if (scanf("%d", &choice) <= 0) break;
        
        if (choice == 1) {
            printf("Index (0-9): "); scanf("%d", &idx);
            printf("Size: "); scanf("%d", &size);
            chunks[idx] = malloc(size);
        } 
        else if (choice == 2) {
            printf("Index (0-9): "); scanf("%d", &idx);
            free(chunks[idx]); 
        } 
        else if (choice == 3) {
            printf("Index (0-9): "); scanf("%d", &idx);
            if (chunks[idx]) printf("Content: %s\n", (char*)chunks[idx]);
        } 
        else if (choice == 4) {
            printf("Index (0-9): "); scanf("%d", &idx);
            printf("Data: ");
            read(0, chunks[idx], 16);
        }
    }
    return 0;
}
