#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

void vuln(char *input) {
    char buf[500];
    strcpy(buf, input);
}

int main() {
    int server, client;
    struct sockaddr_in addr;
    char input[2000];
    int opt = 1;
    socklen_t addrlen = sizeof(addr);

    server = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9999);
    bind(server, (struct sockaddr*)&addr, sizeof(addr));
    listen(server, 5);
    printf("Listening on port 9999\n");
    fflush(stdout);

    while(1) {
        client = accept(server, (struct sockaddr*)&addr, &addrlen);
        char welcome[] = "Welcome to VulnServer\n";
        send(client, welcome, strlen(welcome), 0);

        while(1) {
            memset(input, 0, sizeof(input));
            int n = recv(client, input, sizeof(input)-1, 0);
            if(n <= 0) break;
            input[n] = 0;

            if(strncmp(input, "OVERFLOW1 ", 10) == 0) {
                vuln(input + 10);
                send(client, "OK\n", 3, 0);
            } else if(strncmp(input, "EXIT", 4) == 0) {
                break;
            } else {
                send(client, "UNKNOWN COMMAND\n", 16, 0);
            }
        }
        close(client);
    }
    return 0;
}
