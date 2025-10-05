// COMP 3980 - Assignment 1
// Name: Fereshteh Aghaarabi
// BCIT ID: A01426237
// Date: October 2025
// Program: Diploma of Technology, Datac ommunications
// Description: ELFInspect – Binary-safe ELF file header inspector using POSIX I/O


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

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

// ---------- byte-swap helpers ----------
static inline uint16_t swap16(uint16_t x){ return (x>>8)|(x<<8); }
static inline uint32_t swap32(uint32_t x){ return ((x>>24)&0xff)|((x>>8)&0xff00)|((x<<8)&0xff0000)|((x<<24)&0xff000000); }
static inline uint64_t swap64(uint64_t x){
    return ((uint64_t)swap32((uint32_t)x)<<32) | (uint64_t)swap32((uint32_t)(x>>32));
}

// ---------- safe read ----------
ssize_t safe_read(int fd, void *buf, size_t count) {
    size_t off=0; ssize_t r;
    while (off<count) {
        r=read(fd,(char*)buf+off,count-off);
        if (r>0) off+=(size_t)r;
        else if (r==0) break;
        else if (errno==EINTR) continue;
        else return -1;
    }
    return (ssize_t)off;
}

// ---------- lookup helpers ----------
const char* type_to_string(uint16_t t){
    switch(t){
        case 0:return "None (ET_NONE)";
        case 1:return "Relocatable (ET_REL)";
        case 2:return "Executable (ET_EXEC)";
        case 3:return "Shared Object (ET_DYN)";
        case 4:return "Core (ET_CORE)";
        default:return "Unknown";
    }
}
const char* machine_to_string(uint16_t m){
    switch(m){
        case 3:return "Intel 80386 (EM_386)";
        case 62:return "x86-64 (EM_X86_64)";
        case 40:return "ARM (EM_ARM)";
        case 183:return "AArch64 (EM_AARCH64)";
        default:return "Unknown";
    }
}

// ---------- main ----------
int main(int argc,char*argv[]){
    if(argc!=2){ fprintf(stderr,"Usage: %s <filename>\n",argv[0]); return 1; }
    const char*file=argv[1];
    printf("File: %s\n",file);

    int fd=open(file,O_RDONLY);
    if(fd<0){ printf("Valid ELF: no\nError: cannot open file (%s)\n",strerror(errno)); return 1; }

    struct stat st;
    if(fstat(fd,&st)<0||!S_ISREG(st.st_mode)||st.st_size<52){
        printf("Valid ELF: no\nError: invalid file or too small\n");
        close(fd); return 1;
    }

    unsigned char ident[EI_NIDENT];
    if(safe_read(fd,ident,EI_NIDENT)!=EI_NIDENT){
        printf("Valid ELF: no\nError: cannot read ELF ident\n");
        close(fd); return 1;
    }

    if(!(ident[EI_MAG0]==0x7F&&ident[EI_MAG1]=='E'&&ident[EI_MAG2]=='L'&&ident[EI_MAG3]=='F')){
        printf("Valid ELF: no\nError: Magic number mismatch\n");
        close(fd); return 1;
    }

    int klass=ident[EI_CLASS], data=ident[EI_DATA];
    size_t hdr_size=(klass==ELFCLASS32)?52u:64u;
    unsigned char hdr[64];
    lseek(fd,0,SEEK_SET);
    if(safe_read(fd,hdr,hdr_size)!=(ssize_t)hdr_size){
        printf("Valid ELF: no\nError: truncated ELF header\n");
        close(fd); return 1;
    }

    // read raw fields as little-endian
    uint16_t e_type   = *(uint16_t*)&hdr[16];
    uint16_t e_machine= *(uint16_t*)&hdr[18];
    uint32_t e_version= *(uint32_t*)&hdr[20];
    uint64_t e_entry  = (klass==ELFCLASS32)? *(uint32_t*)&hdr[24] : *(uint64_t*)&hdr[24];

    // if file is Big Endian -> swap bytes
    if(data==ELFDATA2MSB){
        e_type   = swap16(e_type);
        e_machine= swap16(e_machine);
        e_version= swap32(e_version);
        e_entry  = (klass==ELFCLASS32)? swap32((uint32_t)e_entry) : swap64(e_entry);
    }

    printf("Valid ELF: yes\n");
    printf("Magic: %02x %02x %02x %02x\n",ident[0],ident[1],ident[2],ident[3]);
    printf("Class: %s\n", (klass==ELFCLASS64)?"ELF64":(klass==ELFCLASS32)?"ELF32":"Invalid");
    printf("Endianness: %s\n", (data==ELFDATA2LSB)?"Little Endian":(data==ELFDATA2MSB)?"Big Endian":"Invalid");
    printf("Version: %d\n", ident[EI_VERSION]);
    printf("Type: %s\n", type_to_string(e_type));
    printf("Machine: %s\n", machine_to_string(e_machine));
    printf("Entry point: 0x%lx\n",(unsigned long)e_entry);

    close(fd);
    return 0;
}
