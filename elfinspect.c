// elfinspect.c - COMP 3980 Assignment 1
// Simple ELF header inspection using POSIX I/O

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

// ELF constants
#define EI_NIDENT   16
#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6

#define ELFCLASS32  1
#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#define ET_EXEC     2
#define EM_X86_64   62

// helper: safe read loop (handles short reads)
ssize_t safe_read(int fd, void *buf, size_t count) {
    size_t off = 0;
    while (off < count) {
        ssize_t r = read(fd, (char*)buf + off, count - off);
        if (r > 0) off += (size_t)r;
        else if (r == 0) break;        // EOF
        else if (errno == EINTR) continue;
        else return -1;                // error
    }
    return (ssize_t)off;
}

// simple lookup for file type
const char* type_to_string(uint16_t type) {
    switch (type) {
        case 0: return "None (ET_NONE)";
        case 1: return "Relocatable (ET_REL)";
        case 2: return "Executable (ET_EXEC)";
        case 3: return "Shared Object (ET_DYN)";
        case 4: return "Core (ET_CORE)";
        default: return "Unknown";
    }
}

// lookup for machine
const char* machine_to_string(uint16_t machine) {
    switch (machine) {
        case 3:  return "Intel 80386 (EM_386)";
        case 62: return "x86-64 (EM_X86_64)";
        case 40: return "ARM (EM_ARM)";
        case 183:return "AArch64 (EM_AARCH64)";
        default: return "Unknown";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char *file = argv[1];
    printf("File: %s\n", file);

    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        printf("Valid ELF: no\n");
        printf("Error: cannot open file (%s)\n", strerror(errno));
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        printf("Valid ELF: no\n");
        printf("Error: fstat failed\n");
        close(fd);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        printf("Valid ELF: no\n");
        printf("Error: not a regular file\n");
        close(fd);
        return 1;
    }
    if (st.st_size < 52) { // smallest ELF header size
        printf("Valid ELF: no\n");
        printf("Error: file too small\n");
        close(fd);
        return 1;
    }

    unsigned char ident[EI_NIDENT];
    if (safe_read(fd, ident, EI_NIDENT) != EI_NIDENT) {
        printf("Valid ELF: no\n");
        printf("Error: cannot read ELF ident\n");
        close(fd);
        return 1;
    }

    // check magic
    if (!(ident[EI_MAG0] == 0x7F && ident[EI_MAG1] == 'E' &&
          ident[EI_MAG2] == 'L' && ident[EI_MAG3] == 'F')) {
        printf("Valid ELF: no\n");
        printf("Error: Magic number mismatch\n");
        close(fd);
        return 1;
    }

    // class and endianness
    int klass = ident[EI_CLASS];
    int data  = ident[EI_DATA];

    // read full header (32 or 64)
    size_t hdr_size = (klass == ELFCLASS32) ? 52u : 64u;
    unsigned char hdr[64];
    if (lseek(fd, 0, SEEK_SET) < 0) {
        printf("Valid ELF: no\n");
        printf("Error: lseek failed\n");
        close(fd);
        return 1;
    }
    if (safe_read(fd, hdr, hdr_size) != (ssize_t)hdr_size) {
        printf("Valid ELF: no\n");
        printf("Error: truncated ELF header\n");
        close(fd);
        return 1;
    }

    // get fields (assume little endian for simplicity)
    uint16_t e_type = (uint16_t)hdr[16] | (uint16_t)(hdr[17] << 8);
    uint16_t e_machine = (uint16_t)hdr[18] | (uint16_t)(hdr[19] << 8);

    uint32_t e_version = (uint32_t)hdr[20]
                       | ((uint32_t)hdr[21] << 8)
                       | ((uint32_t)hdr[22] << 16)
                       | ((uint32_t)hdr[23] << 24);

    uint64_t e_entry;
    if (klass == ELFCLASS32) {
        e_entry = (uint32_t)hdr[24]
                | ((uint32_t)hdr[25] << 8)
                | ((uint32_t)hdr[26] << 16)
                | ((uint32_t)hdr[27] << 24);
    } else {
        e_entry = 0;
        for (int i = 0; i < 8; i++) {
            e_entry |= ((uint64_t)hdr[24+i]) << (8*i);
        }
    }

    // Print structured output
    printf("Valid ELF: yes\n");
    printf("Magic: %02x %02x %02x %02x\n",
           ident[EI_MAG0], ident[EI_MAG1], ident[EI_MAG2], ident[EI_MAG3]);

    if (klass == ELFCLASS64)
        printf("Class: ELF64\n");
    else if (klass == ELFCLASS32)
        printf("Class: ELF32\n");
    else
        printf("Class: Invalid (%d)\n", klass);

    if (data == ELFDATA2LSB)
        printf("Endianness: Little Endian\n");
    else if (data == ELFDATA2MSB)
        printf("Endianness: Big Endian\n");
    else
        printf("Endianness: Invalid (%d)\n", data);

    printf("Ident Version: %d\n", ident[EI_VERSION]);
    printf("Type: %s\n", type_to_string(e_type));
    printf("Machine: %s\n", machine_to_string(e_machine));
    printf("Entry point: 0x%lx\n", (unsigned long)e_entry);

    close(fd);
    return 0;
}
