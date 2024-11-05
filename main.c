#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include <errno.h>
#include <linux/limits.h>
#include <sodium.h>
#include <termios.h>
#include <memory.h>

enum ErrorCode {
    ERROR_FILE_NOT_FOUND = 27,
    ERROR_DERIVING_KEY,
    ERROR_ENCRYPTION_DECRYPTION,
    ERROR_WRITING,
    ERROR_READING,
    ERROR_PWD_MISMATCH,
    ERROR_MAX_N_PWDS_REACHED,
    ERROR_PASSWORD_TOO_LONG,
    ERROR_USERNAME_TOO_LONG,
    ERROR_PLATFORM_TOO_LONG,
    ERROR_OUT_OF_MEMORY,
    ERROR_INVALID_ARG_COUNT,
    ERROR_ADDING_ENTRY,
    ERROR_DB_ALREADY_EXISTS
};

/* General args */
#define PROG_NAME_ARG 0
#define CMD_ARG 1
#define DB_PATH_ARG 2

/* Add entry args */
#define PLATFORM_ARG 3
#define USERNAME_ARG 4
#define PASSWORD_ARG 5

/* Search entry args */
#define SEARCH_TERM_ARG 3

/* Defined length in bytes for some buffers */
#define MAX_PLATFORM_LEN 256
#define MAX_USERNAME_LEN 256
#define MAX_PASSWORD_LEN 64
#define MAX_N_ENTRIES 512

#define DEFAULT_PWD_GEN_SIZE 21

typedef struct {
    char platform[MAX_PLATFORM_LEN];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    size_t platform_len;
    size_t username_len;
    size_t password_len;
} DBEntry;

typedef struct {
    int n_entries;
    char nonce[crypto_stream_xchacha20_NONCEBYTES];
    char salt[crypto_pwhash_SALTBYTES];
    char pwdhash[crypto_pwhash_STRBYTES];
} DBMetadata;

int compare_entries(const void *arg1, const void *arg2);
volatile void *sec_memcpy(volatile void *dst, const volatile void *src, size_t len);
int write_db(const char *master_password, const char *db_path, const DBEntry *entries, int n_entries);
int read_db(const char *master_password, const char *db_path, DBEntry *out_entries, DBMetadata *out_metadata);
int derive_key(const char *master_password, unsigned char *salt, unsigned char *key);
bool pwd_match(const char *master_password, const DBMetadata *metadata);
bool find_db(const char *db);
bool prompt(const char *prompt_text, char *out, size_t buffer_size, bool echo);
void toggle_echo(bool new_state);
bool add_entry(const char *platform, const char *username, const char *password, DBEntry *entries, DBMetadata *metadata);
int handle_cmd_create(const char *master_password, const char *db_path);
int handle_cmd_add(const char *master_password, const char *db_path, const char *platform, const char *username, const char *password);
int handle_cmd_list(const char *master_password, const char *db_path);
void secure_copy_entry(DBEntry *to, DBEntry *from);
int handle_cmd_search(const char *master_password, const char *db_path, const char *search_term, DBEntry *out_entry);
void gen_random_password(char *password, size_t length);
int handle_commands(const char *master_password, int argc, char *argv[], bool db_exists);

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        return EXIT_FAILURE;
    }

    // Usage: pwd <path> <cmd>
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <path> <cmd>\n", argv[0]);
        return EXIT_FAILURE;
    };

    const char *db_path = argv[DB_PATH_ARG];

    // Prompt for a master password
    char *mpass = (char *)sodium_malloc(MAX_PASSWORD_LEN * sizeof(char));
    if (!prompt("Enter a master password: ", mpass, MAX_PASSWORD_LEN * sizeof(char), false)) {
        fprintf(stderr, "Failed to read master password from stdin.\n");
        sodium_free(mpass);

        return EXIT_FAILURE;
    }

    // Verify DB path is within length limit
    size_t path_len = strlen(db_path);
    if (path_len >= PATH_MAX) {  // PATH_MAX includes null, so >=
        fprintf(stderr, "Path length %d is beyond the max path length.\n", (int)path_len);
        sodium_free(mpass);

        return EXIT_FAILURE;
    }

    // Check whether DB file already exists
    bool db_exists = find_db(db_path);

    // Command handler
    int status = handle_commands(mpass, argc, argv, db_exists);

    printf(status == 0 ? "Success.\n" : "Failed.\n");

    sodium_free(mpass);
    return (status == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

int compare_entries(const void *arg1, const void *arg2) {
    DBEntry d1 = *(DBEntry *)arg1;
    DBEntry d2 = *(DBEntry *)arg2;

    return strcasecmp(d1.platform, d2.platform);
}

volatile void *sec_memcpy(volatile void *dst, const volatile void *src, size_t len) {
    volatile char *cdst, *csrc;

    cdst = (volatile char *)dst;
    csrc = (volatile char *)src;

    while (len--) {
        cdst[len] = csrc[len];
    }

    return dst;
}

int write_db(const char *master_password, const char *db_path, const DBEntry *entries, int n_entries) {
    /*
     * If the data already exists on the disk, remove it before writing the new
     * encrypted data.
     */
    if (remove(db_path) != 0) {
        switch (errno) {
            case ENOENT:
                break;
            default:
                return errno;
        }
    }

    // Generate salt, nonce and key for encryption
    DBMetadata *metadata = (DBMetadata *)malloc(sizeof(DBMetadata));
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    unsigned char *key = sodium_allocarray(crypto_stream_xchacha20_KEYBYTES, sizeof(unsigned char));

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    if (derive_key(master_password, salt, key) != 0) {
        sodium_free(key);
        free(metadata);

        return ERROR_DERIVING_KEY;
    }

    // Generate a hash of the master password to add to metadata
    char pwdhash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(pwdhash, master_password, strlen(master_password), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        // Ran out of memory
        sodium_free(key);
        free(metadata);

        return ERROR_OUT_OF_MEMORY;
    }

    // Write random bytes to nonce buffer; need to write the nonce metadata to file and later used in encryption
    randombytes_buf(nonce, crypto_stream_xchacha20_NONCEBYTES);

    // Move salt, nonce and hash of master password to the metadata struct
    memcpy(metadata->salt, salt, crypto_pwhash_SALTBYTES);
    memcpy(metadata->nonce, nonce, crypto_stream_xchacha20_NONCEBYTES);
    memcpy(metadata->pwdhash, pwdhash, crypto_pwhash_STRBYTES);
    metadata->n_entries = n_entries;

    // Encrypt database data
    size_t db_size = MAX_N_ENTRIES * sizeof(DBEntry);
    unsigned char *ciphertext = (unsigned char *)malloc(db_size);
    if (entries != NULL) {
        if (crypto_stream_xchacha20_xor(ciphertext, (unsigned char *)entries, db_size, nonce, key) != 0) {
            sodium_free(key);
            free(ciphertext);
            free(metadata);

            return ERROR_ENCRYPTION_DECRYPTION;
        }
    }

    // prepare to write binary data
    FILE *file = fopen(db_path, "wb");
    if (!file) {
        sodium_free(key);
        free(ciphertext);
        free(metadata);

        return errno;
    }

    // Write metadata to file
    size_t written = fwrite(metadata, 1, sizeof(DBMetadata), file);
    if (written != sizeof(DBMetadata)) {
        fclose(file);
        sodium_free(key);
        free(ciphertext);
        free(metadata);

        return ERROR_WRITING;
    }

    // Write encrypted database entries as a char array to file
    if (entries != NULL) {
        written = fwrite(ciphertext, 1, db_size, file);
        if (written != db_size) {
            fclose(file);
            sodium_free(key);
            free(ciphertext);
            free(metadata);

            return ERROR_WRITING;
        }
    }

    fclose(file);
    sodium_free(key);
    free(ciphertext);
    free(metadata);

    return 0;
}

int read_db(const char *master_password, const char *db_path, DBEntry *out_entries, DBMetadata *out_metadata) {
    // Prepare to read the database
    FILE *file = fopen(db_path, "rb");
    if (!file) {
        return errno;
    }

    if (fread(out_metadata, 1, sizeof(DBMetadata), file) != sizeof(DBMetadata)) {
        fclose(file);

        return ERROR_READING;
    }

    // Compare password hashes
    if (!pwd_match(master_password, out_metadata)) {
        fclose(file);
        fprintf(stderr, "Password incorrect.\n");

        return ERROR_PWD_MISMATCH;
    }

    if (out_metadata->n_entries > 0) {
        unsigned char *key = sodium_allocarray(crypto_stream_xchacha20_KEYBYTES, sizeof(char));

        if (derive_key(master_password, (unsigned char *)out_metadata->salt, key) != 0) {
            sodium_free(key);
            fclose(file);

            return ERROR_DERIVING_KEY;
        }

        unsigned char *data = (unsigned char *)sodium_malloc(MAX_N_ENTRIES * sizeof(DBEntry));
        if (fread(data, 1, MAX_N_ENTRIES * sizeof(DBEntry), file) != (MAX_N_ENTRIES * sizeof(DBEntry))) {
            sodium_free(key);
            sodium_free(data);
            fclose(file);

            return ERROR_READING;
        }

        // XChaCha20 decryption
        if (crypto_stream_xchacha20_xor(data, data, MAX_N_ENTRIES * sizeof(DBEntry), (const unsigned char *)out_metadata->nonce, key) != 0) {
            sodium_free(key);
            sodium_free(data);
            fclose(file);

            return ERROR_ENCRYPTION_DECRYPTION;
        }
        sec_memcpy(out_entries, (DBEntry *)data, MAX_N_ENTRIES * sizeof(DBEntry));

        // Add null termination
        for (size_t i = 0; i < out_metadata->n_entries; i++) {
            out_entries[i].platform[out_entries[i].platform_len] = '\0';
            out_entries[i].username[out_entries[i].username_len] = '\0';
            out_entries[i].password[out_entries[i].password_len] = '\0';
        }

        sodium_free(key);
        sodium_free(data);
    }
    fclose(file);

    return 0;
}

/*
 * Derive an XChaCha20 secret key from a master password, for key derivation.
 *
 * Return integer 0 to indicate successful derivation of a key, return
 * ERROR_DERIVING_KEY otherwise.
 *
 */
int derive_key(const char *master_password, unsigned char *salt, unsigned char *key) {
    if (crypto_pwhash(
        key, crypto_stream_xchacha20_KEYBYTES, master_password, strlen(master_password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
            return ERROR_DERIVING_KEY;
    }

    return 0;
}

/*
 * Verify whether the hash of the master password matches the hash in the
 * pwdhash field of metadata. Return true if the hashes match
 */
bool pwd_match(const char *master_password, const DBMetadata *metadata) {
    return crypto_pwhash_str_verify(metadata->pwdhash, master_password,
                                    strlen(master_password)) == 0;
}

bool find_db(const char *db) {
    if (access(db, F_OK) == -1) {
        return false;
    } else {
        return true;
    }
}

bool prompt(const char *prompt_text, char *out, size_t buffer_size, bool echo) {
    printf("%s", prompt_text);
    bool valid = false;
    if (echo) {
        valid = fgets(out, buffer_size, stdin) != NULL;
    } else {
        toggle_echo(false);
        valid = fgets(out, buffer_size, stdin) != NULL;
        toggle_echo(true);
    }
    printf("\n");
    out[strcspn(out, "\n")] = 0;

    return valid;
}

void toggle_echo(bool new_state) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);

    if (!new_state) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

/*
    Create a new entry in entries and update metadata to reflect the change.
*/
bool add_entry(const char *platform, const char *username, const char *password, DBEntry *entries, DBMetadata *metadata) {
    if (metadata->n_entries >= MAX_N_ENTRIES) {
        return false;
    }

    DBEntry *new_entry = (DBEntry *)sodium_malloc(sizeof(DBEntry));

    // Copy platform, username and password into new_entry struct
    size_t platform_len = strlen(platform);
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    sec_memcpy(new_entry->platform, platform, platform_len);
    sec_memcpy(new_entry->username, username, username_len);
    sec_memcpy(new_entry->password, password, password_len);

    // Store lengths in the new_entry struct
    new_entry->platform_len = platform_len;
    new_entry->username_len = username_len;
    new_entry->password_len = password_len;

    // Update entries and metadata
    entries[metadata->n_entries] = *new_entry;
    metadata->n_entries++;

    sodium_free(new_entry);

    return true;
}

/*
    Create a database with zero entries. 
    Assume no database already exists at db_path.
*/
int handle_cmd_create(const char *master_password, const char *db_path) {
    DBEntry *entries = (DBEntry *)sodium_malloc(MAX_N_ENTRIES * sizeof(DBEntry));
    int write_status = write_db(master_password, db_path, entries, 0);
    sodium_free(entries);

    return write_status;
}

/*
    Add an entry to an existing database.
    Assume this database already exists.
*/
int handle_cmd_add(const char *master_password, const char *db_path, const char *platform, const char *username, const char *password) {
    DBEntry *entries = (DBEntry *)sodium_malloc(MAX_N_ENTRIES * sizeof(DBEntry));
    DBMetadata metadata;
    int read_status = read_db(master_password, db_path, entries, &metadata);

    if (read_status == 0) {
        bool add_success = add_entry(platform, username, password, entries, &metadata);

        if (add_success) {
            // Sort
            qsort(entries, metadata.n_entries, sizeof(DBEntry), compare_entries);

            // Write to the database file
            int write_status = write_db(master_password, db_path, entries, metadata.n_entries);
            sodium_free(entries);

            return write_status;
        }
        sodium_free(entries);

        return ERROR_ADDING_ENTRY;
    } else {
        sodium_free(entries);

        return read_status;
    }
}

int handle_cmd_list(const char *master_password, const char *db_path) {
    DBEntry *entries = (DBEntry *)sodium_malloc(MAX_N_ENTRIES * sizeof(DBEntry));
    DBMetadata metadata;
    int read_status = read_db(master_password, db_path, entries, &metadata);

    if (read_status == 0) {
        // List entries
        if (metadata.n_entries == 0) {
            printf("No entries to display.\n");
        } else {
            printf("Platform\tUsername\tPassword\n");
            for (size_t i = 0; i < metadata.n_entries; i++) {
                printf("%s\t%s\t%s\n", entries[i].platform, entries[i].username, entries[i].password);
            }
        }
    }
    sodium_free(entries);

    return read_status;
}

void secure_copy_entry(DBEntry *to, DBEntry *from) {
    sec_memcpy(to->platform, from->platform, from->platform_len);
    sec_memcpy(to->username, from->username, from->username_len);
    sec_memcpy(to->password, from->password, from->password_len);

    to->platform[from->platform_len] = '\0';
    to->username[from->username_len] = '\0';
    to->password[from->password_len] = '\0';
}

/*
    Search for a particular entry
*/
int handle_cmd_search(const char *master_password, const char *db_path, const char *search_term, DBEntry *out_entry) {
    DBEntry *entries = (DBEntry *)sodium_malloc(MAX_N_ENTRIES * sizeof(DBEntry));
    DBMetadata metadata;
    int read_status = read_db(master_password, db_path, entries, &metadata);

    if (read_status != 0) {
        sodium_free(entries);

        return read_status;
    }

    /* Entries are sorted -> binary search */
    if (metadata.n_entries == 0) {
        sodium_free(entries);
        return -1;
    } else if (metadata.n_entries == 1 && strcasecmp(entries[0].platform, search_term) == 0) {
        secure_copy_entry(out_entry, &entries[0]);

        sodium_free(entries);
        return 0;
    } else {
        int l = 0;
        int r = metadata.n_entries-1;

        // Binary search
        while (l <= r) {
            int mid = (l + r) / 2;
            int cmp = strcasecmp(entries[mid].platform, search_term);
            if (cmp == 0) {
                secure_copy_entry(out_entry, &entries[mid]);

                sodium_free(entries);
                return 0;
            }

            if (cmp > 0) {
                r = mid - 1;
            } else if (cmp < 0) {
                l = mid + 1;
            }
        }

        sodium_free(entries);
        return -1;
    }
}

/*
    Generate a random password using randombytes_uniform
*/
void gen_random_password(char *password, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
//                            "!@#$%^&*()-_=+[]{}|;:,.<>?";
                            "!@#$^&*()-_=+[]{}|;:,.<>?";
    size_t charset_size = sizeof(charset)-1;

    for (size_t i = 0; i < length; i++) {
        password[i] = charset[randombytes_uniform(charset_size)];
    }

    password[length] = '\0';
}

int handle_commands(const char *master_password, int argc, char *argv[], bool db_exists) {
    const char *db_path = argv[DB_PATH_ARG];
    const char *cmd = argv[CMD_ARG];

    int status;
    if (!db_exists && strcmp(cmd, "create") == 0) {
        status = handle_cmd_create(master_password, db_path);
    } else if (strcmp(cmd, "add") == 0) {
        char *pwd = (char *)sodium_malloc(MAX_PASSWORD_LEN);

        // prog <path> <cmd> <platform> <username> <password>
        if (argc < USERNAME_ARG+1) {
            return ERROR_INVALID_ARG_COUNT;
        } else if (argc < PASSWORD_ARG+1) {
            // No password provided: generate one
            assert(DEFAULT_PWD_GEN_SIZE <= MAX_PASSWORD_LEN);
            gen_random_password(pwd, DEFAULT_PWD_GEN_SIZE);
        } else {
            size_t password_length = strlen(argv[PASSWORD_ARG]);
            if (password_length >= MAX_PASSWORD_LEN) {
                return ERROR_PASSWORD_TOO_LONG;
            }

            sec_memcpy(pwd, argv[PASSWORD_ARG], password_length);
            pwd[password_length] = '\0';
        }
        const char *platform = argv[PLATFORM_ARG];
        const char *username = argv[USERNAME_ARG];

        /* Ensure platform and username are also correctly formatted */
        if (strlen(platform) >= MAX_PLATFORM_LEN) {
            sodium_free(pwd);
            
            return ERROR_PLATFORM_TOO_LONG;
        }
        if (strlen(username) >= MAX_USERNAME_LEN) {
            sodium_free(pwd);

            return ERROR_USERNAME_TOO_LONG;
        }

        status = handle_cmd_add(master_password, db_path, platform, username, pwd);
        sodium_free(pwd);
    } else if (db_exists && strcmp(cmd, "list") == 0) {
        status = handle_cmd_list(master_password, db_path);
    } else if (db_exists && strcmp(cmd, "search") == 0) {
        if (argc < SEARCH_TERM_ARG+1) {
            return ERROR_INVALID_ARG_COUNT;
        }
        const char *search_term = argv[SEARCH_TERM_ARG];
        DBEntry *entry = (DBEntry *)sodium_malloc(sizeof(DBEntry));
        status = handle_cmd_search(master_password, db_path, search_term, entry);

        if (status == 0) {
            printf("%s\t%s\t%s\n", entry->platform, entry->username, entry->password);
        }

        sodium_free(entry);
    } else {
        status = -1;    // Invalid command
    }

    return status;
}

