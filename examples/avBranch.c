#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 128

// Function read the file into a buffer
void read_file(char *file_name, char *buffer, int size)
{
    FILE * f;
    size_t result;

    f = fopen (file_name, "rb" );
    if (f==NULL) 
    {
        printf("Can't open %s\n", file_name);
        exit (1);
    }
    result = fread (buffer,1,size,f);
    if (result != size) 
        printf("Read bytes %lu < %d\n", result, size);
    printf("Buffer address %p\n", buffer);
    fclose (f);
}

struct header
{
    char sync[16];
    char magic[4];
    unsigned char tainted;
    char data[1];
};

void test_avBranch(char *buf)
{
    struct header *h = (struct header *)buf;    

    //if(memcmp(&h->magic, "AVBR", 4) != 0)
    if(!(h->magic[0] == 'A' && h->magic[1] == 'V' && h->magic[2] == 'B' && h->magic[3] == 'R'))
    {
        printf("bad magic\n");
        return;
    }
    else
    {
        void (*p)();
        // The value is tainted to the address
        if (h->tainted < 128)
            p = (void*)(unsigned long)(0xFFFFFF00 + h->data[0]);
        else
            p = (void*)(unsigned long)(0xFFFFFF00);
        p();
    }
}


int main(int argc, char *argv[])
{
    char *type;
    char buf[BUFFER_SIZE];
  
    if(argc != 2)
    {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    memset(buf, 0, sizeof(char)*BUFFER_SIZE);
    read_file(argv[1], buf, BUFFER_SIZE);

    test_avBranch(buf);
}