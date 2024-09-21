#include <stdio.h>
#include <string.h>

// build flags: -g -fomit-frame-pointer -no-pie -fno-stack-protector

FILE *fd;

int main(int argc, char **argv)
{
    char buf[40];
    if (argc != 2) {
        return 0;
    }
    fd = fopen(argv[1], "r");
    fread(buf, 1, 100, fd);
    fclose(fd);
    return 0;
}

