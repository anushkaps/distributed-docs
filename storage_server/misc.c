#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *append_file_dynamic(const char *filepath, char *buf, size_t *buf_size, size_t *len)
{
    FILE *f = fopen(filepath, "r");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    size_t required = *len + file_size + 1;
    if (required > *buf_size)
    {
        char *new_buf = realloc(buf, required);
        if (!new_buf)
        {
            fclose(f);
            return NULL;
        }
        buf = new_buf;
        *buf_size = required;
    }

    fread(buf + *len, 1, file_size, f);
    fclose(f);

    *len += file_size;
    buf[*len] = '\0';

    return buf;
}
