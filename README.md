# Minimal password manager
## Description
A minimal CLI password manager written in C. I suggest that you do not ever use this seriously --- there are already tried and tested tools for this task, and I am not a professional in cybersecurity.
Nonetheless, this has been a fun project to endeavour on, and I welcome any feedback.

## Build instructions
1. Install the `libsodium-dev` dependency.
2. Change to the project root directory and `make`.

## Quick docs
### create
Usage: `pmg create <db_path>`
Create a password database at `db_path`. `db_path` must not already be a file.

### add
Usage:
- **1** `pmg add <db_path> <platform> <username> <password>`. Add entry to a database at `<db_path>` with platform=`<platform>`, username=`<username>` and password=`<password>`.
- **2** `pmg add <db_path> <platform> <username>`. Add entry to a databse at `<db_path>` with platform=`<platform>` and username=`<username>`. A password of length 21 is automatically generated.

### list
Usage: `pmg list <db_path>`
List all of the entries which exist in the database at `db_path`.

### search
Usage: `pmg search <db_path> <search_term>`
Search for an exact match between `<search_term>` and the platform of an entry in the database at `<db_path>`.
