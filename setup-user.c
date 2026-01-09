/* setup-user.c
   Robust Alpine-friendly user creation tool (run as root).
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define MAX 256

static int safe_username(const char *u) {
    if (!u || !*u) return 0;
    size_t len = strlen(u);
    if (len < 1 || len > 32) return 0;
    for (size_t i = 0; i < len; ++i) {
        char c = u[i];
        if (c == '/' || c == ' ' || c == '\t' || c == '\n' || c == ':') return 0;
    }
    return 1;
}

int main(void) {
    char username[MAX];
    char password[MAX];
    char cmd[1024];
    struct passwd *pw = NULL;
    int rc;

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return 1;
    }

    printf("Enter username for new user account: ");
    if (!fgets(username, sizeof(username), stdin)) return 1;
    username[strcspn(username, "\n")] = 0;

    if (!safe_username(username)) {
        fprintf(stderr, "Invalid username. Avoid slashes, spaces, colons, and keep length 1-32.\n");
        return 1;
    }

    printf("Enter password: ");
    if (!fgets(password, sizeof(password), stdin)) return 1;
    password[strcspn(password, "\n")] = 0;

    /* Create the user explicitly setting home and shell. Use -D to not prompt for password. */
    snprintf(cmd, sizeof(cmd),
             "adduser -D -h /home/%s -s /bin/ash %s >/dev/null 2>&1",
             username, username);

    rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "Failed to create user (adduser returned %d).\n", rc);
        return 1;
    }

    /* Verify user exists and retrieve uid/gid */
    pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "User creation appeared to succeed but user not found in /etc/passwd.\n");
        return 1;
    }

    /* Try setting the password with chpasswd first, fallback to passwd if needed */
    snprintf(cmd, sizeof(cmd),
             "printf \"%s:%s\\n\" \"%s\" \"%s\" | chpasswd >/dev/null 2>&1",
             username, password, username, password);

    rc = system(cmd);
    if (rc != 0) {
        snprintf(cmd, sizeof(cmd),
                 "printf \"%s\\n%s\\n\" \"%s\" \"%s\" | passwd %s >/dev/null 2>&1",
                 password, password, password, password, username);
        rc = system(cmd);
        if (rc != 0) {
            fprintf(stderr, "Failed to set password for user '%s'.\n", username);
            snprintf(cmd, sizeof(cmd), "deluser --force --remove-home %s >/dev/null 2>&1", username);
            system(cmd);
            memset(password, 0, sizeof(password));
            return 1;
        }
    }

    /* Ensure home dir exists, copy profile if present, and fix ownership/permissions */
    snprintf(cmd, sizeof(cmd), "/bin/mkdir -p /home/%s >/dev/null 2>&1", username);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "if [ -f /home/user/.profile ]; then cp /home/user/.profile /home/%s/.profile; fi", username);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "chown -R %s:%s /home/%s >/dev/null 2>&1", username, username, username);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "chmod 700 /home/%s >/dev/null 2>&1", username);
    system(cmd);

    printf("\nUser '%s' created successfully.\n", username);
    printf("Restart the system to log in.\n");

    memset(password, 0, sizeof(password));
    return 0;
}
