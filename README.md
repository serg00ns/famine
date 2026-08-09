# famine

`famine` is a C/assembly-based educational ELF-infector prototype that scans files, marks already signed files, and applies a light injection payload to other files.

## What it does
- Scans from `/` recursively.
- Skips sensitive system directories (`/proc`, `/sys`, `/dev`, `/run`, `/mnt`, `/media`) and symbolic links.
- Detects already infected files by checking a file trailer signature.
- For ELF files: appends payload bytes to the executable section metadata and updates the entry point.
- For non-ELF regular files: writes a marker/trailer signature.
- Uses a lock file (`/tmp/famine.run.lock`) to avoid concurrent executions.

## Build
```sh
make
```

## Run
```sh
./Famine
```

## Entry points
- `main.c`: startup/locking logic, calls scan routine.
- `mmap_scan.c`: directory recursion and infection flow.
- `pack.c`: signature checks and infection write logic.
- `famine.h`: shared types, constants, and function prototypes.
- `payload.asm`: payload stub bytes.

## Notes
This project is intended for a controlled VM or lab environment only.
