/*
 * Salted-hash password storage with login attempt limiting
 * for an embedded Linux device.
 *
 * Coursework project, Embedded Systems Security
 * Fujian Police College, autumn 2025
 *
 * Build:
 *   gcc -o password_auth password_auth.c -lcrypto
 *
 * Requires OpenSSL development headers (libssl-dev).
 * Tested on Ubuntu 22.04.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Core configuration constants */
#define MAX_FAILED 3                    /* maximum failed attempts */
#define LOCK_TIME 10                    /* lockout duration, seconds */
#define SALT_LEN 8                      /* salt length */
#define CONFIG_FILE "user_config.txt"   /* user credential file */
#define FAILED_FILE "failed_count.txt"  /* failed attempt counter */

/* Terminal colour codes */
#define RED    "\033[31m"
#define GREEN  "\033[32m"
#define YELLOW "\033[33m"
#define BLUE   "\033[34m"
#define RESET  "\033[0m"

/* Clear the terminal */
void clear_screen() {
    system("clear");
}

/* Generate an 8-character random salt */
void generate_salt(char *salt) {
    char chars[] =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand((unsigned int)time(NULL) ^ getpid());
    for (int i = 0; i < SALT_LEN; i++) {
        salt[i] = chars[rand() % (sizeof(chars) - 1)];
    }
    salt[SALT_LEN] = '\0';
}

/* Compute SHA-256 over password concatenated with salt */
void compute_hash(char *password, char *salt, char *hash) {
    char combo[100];
    /* snprintf bounds the write, preventing buffer overflow */
    snprintf(combo, sizeof(combo), "%s%s", password, salt);

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)combo, strlen(combo), sha256_hash);

    /* Convert to a 64-character hexadecimal string */
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash[i * 2], "%02x", sha256_hash[i]);
    }
    hash[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/* Registration: password confirmation, salt generation, credential storage */
void register_user() {
    char username[20], password[20], confirm_pwd[20];
    char salt[SALT_LEN + 1], hash[65];
    FILE *fp;

    clear_screen();
    printf(BLUE "========================================\n" RESET);
    printf(BLUE "            User Registration           \n" RESET);
    printf(BLUE "========================================\n" RESET);

    /* Bounded read prevents overflow */
    printf("Username (max 20 chars): ");
    if (scanf("%19s", username) != 1) {
        printf(RED "Error: invalid username input.\n" RESET);
        sleep(2);
        return;
    }

    printf("Password (max 20 chars): ");
    if (scanf("%19s", password) != 1) {
        printf(RED "Error: invalid password input.\n" RESET);
        sleep(2);
        return;
    }

    printf("Confirm password: ");
    if (scanf("%19s", confirm_pwd) != 1) {
        printf(RED "Error: invalid confirmation input.\n" RESET);
        sleep(2);
        return;
    }

    if (strcmp(password, confirm_pwd) != 0) {
        printf(RED "Error: passwords do not match.\n" RESET);
        sleep(2);
        return;
    }

    generate_salt(salt);
    compute_hash(password, salt, hash);

    fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        printf(RED "Error: could not create config file. "
                   "Check directory permissions.\n" RESET);
        perror("fopen error");
        sleep(3);
        return;
    }
    /* Strict "username:salt:hash" format, no trailing characters */
    fprintf(fp, "%s:%s:%s", username, salt, hash);
    fflush(fp);
    fclose(fp);
    system("chmod 600 " CONFIG_FILE);

    fp = fopen(FAILED_FILE, "w");
    if (!fp) {
        printf(RED "Error: could not create counter file.\n" RESET);
        perror("fopen error");
        sleep(3);
        return;
    }
    fprintf(fp, "0");
    fflush(fp);
    fclose(fp);
    system("chmod 600 " FAILED_FILE);

    printf(GREEN "Registration successful. Stored username: %s\n" RESET,
           username);
    printf(YELLOW "Returning to main menu in 2 seconds...\n" RESET);
    sleep(2);
}

/* Login: lockout check, credential parsing, hash comparison */
void login_user() {
    char stored_user[20], salt[SALT_LEN + 1];
    char stored_hash[65], computed_hash[65];
    char input_user[20], input_pwd[20];
    int failed_count = 0;
    FILE *fp;

    clear_screen();
    printf(BLUE "========================================\n" RESET);
    printf(BLUE "               User Login               \n" RESET);
    printf(BLUE "========================================\n" RESET);

    fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        printf(RED "Error: no registered user found. "
                   "Please register first.\n" RESET);
        sleep(2);
        return;
    }
    fclose(fp);

    /* Read the persisted failure count */
    fp = fopen(FAILED_FILE, "r");
    if (fp) {
        fscanf(fp, "%d", &failed_count);
        fclose(fp);
    } else {
        fp = fopen(FAILED_FILE, "w");
        fprintf(fp, "0");
        fclose(fp);
        failed_count = 0;
    }

    /* Lockout state */
    if (failed_count >= MAX_FAILED) {
        printf(YELLOW "Warning: too many failed attempts. "
                      "Account locked for %d seconds.\n" RESET, LOCK_TIME);
        for (int i = LOCK_TIME; i > 0; i--) {
            printf(YELLOW "Time remaining: %d s\r" RESET, i);
            fflush(stdout);
            sleep(1);
        }
        fp = fopen(FAILED_FILE, "w");
        fprintf(fp, "0");
        fclose(fp);
        printf(GREEN "\nLock released. Please try again.\n" RESET);
        sleep(1);
        return;
    }

    /* Parse the stored record on ':' boundaries.
       Reading the whole line into the username field was the original bug. */
    fp = fopen(CONFIG_FILE, "r");
    fscanf(fp, "%19[^:]:%8[^:]:%64s", stored_user, salt, stored_hash);
    fclose(fp);

    printf("Username: ");
    if (scanf("%19s", input_user) != 1) {
        printf(RED "Error: invalid username input.\n" RESET);
        sleep(2);
        return;
    }

    /* Debug output, removed for production:
       this printed the stored username to the terminal.
    printf(YELLOW "Debug: entered=%s, stored=%s\n" RESET,
           input_user, stored_user);
    */

    if (strcmp(input_user, stored_user) != 0) {
        failed_count++;
        printf(RED "Error: incorrect username.\n" RESET);
        printf(YELLOW "Attempts remaining: %d\n" RESET,
               MAX_FAILED - failed_count);
        fp = fopen(FAILED_FILE, "w");
        fprintf(fp, "%d", failed_count);
        fclose(fp);
        sleep(2);
        return;
    }

    printf("Password: ");
    if (scanf("%19s", input_pwd) != 1) {
        printf(RED "Error: invalid password input.\n" RESET);
        sleep(2);
        return;
    }

    compute_hash(input_pwd, salt, computed_hash);

    if (strcmp(computed_hash, stored_hash) == 0) {
        printf(GREEN "========================================\n" RESET);
        printf(GREEN "             Login successful           \n" RESET);
        printf(GREEN "========================================\n" RESET);
        fp = fopen(FAILED_FILE, "w");
        fprintf(fp, "0");
        fclose(fp);
        sleep(3);
    } else {
        failed_count++;
        printf(RED "Error: incorrect password.\n" RESET);
        printf(YELLOW "Attempts remaining: %d\n" RESET,
               MAX_FAILED - failed_count);
        fp = fopen(FAILED_FILE, "w");
        fprintf(fp, "%d", failed_count);
        fclose(fp);
        sleep(2);
    }
}

/* Interactive main menu loop */
void show_main_menu() {
    int choice;

    while (1) {
        clear_screen();
        printf(BLUE "========================================\n" RESET);
        printf(BLUE "   Embedded Linux Password Protection   \n" RESET);
        printf(BLUE "========================================\n" RESET);
        printf(GREEN "                Main menu               \n" RESET);
        printf("1. Register\n");
        printf("2. Log in\n");
        printf("0. Exit\n");
        printf(BLUE "========================================\n" RESET);
        printf("Select (0-2): ");

        /* Guard against non-numeric input causing an infinite loop */
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf(RED "Error: please enter 0, 1 or 2.\n" RESET);
            sleep(2);
            continue;
        }

        switch (choice) {
            case 1:
                register_user();
                break;
            case 2:
                login_user();
                break;
            case 0:
                clear_screen();
                printf(GREEN "========================================\n" RESET);
                printf(GREEN "                 Goodbye                \n" RESET);
                printf(GREEN "========================================\n" RESET);
                exit(0);
            default:
                printf(RED "Error: please select a number between 0 and 2.\n"
                       RESET);
                sleep(2);
                break;
        }
    }
}

int main() {
    srand((unsigned int)time(NULL));
    show_main_menu();
    return 0;
}
