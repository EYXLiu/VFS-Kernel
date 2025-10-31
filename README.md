# Virtual Ram File System Kernel written in C
A Linux kernel module providing a fully in-memory virtual filesystem for high-performance file management and OS-level experimentation <br/>

# Compile
- `make` <br/>
- `sudo insmod vfs.ko` <br/>
- `dmesg | tail -n 20` for logs <br/>
- `sudo rmmod vfs.ko` <br/>
- `make clean` <br/>

# Features
Create, read, write, and delete files in RAM <br/>
Memory-backed storage with dynamic allocation <br/>
Basic file metadata (size, RAM) <br/>
User-interaction through `/proc` and `/sys` <br/>
- `/proc/vfs` for all files and names <br/>
- `/proc/vfs/mem` for the memory use of each file <br/>
- `/proc/vfs/<filename>` to read the contents of each file <br/>
- `/sys/kernel/vfs/num_files` to get the current number of files <br/>
- `/sys/kernel/vfs/max_files` to get the maximum number of files it can store <br/>

# Improvements
Concurrency (if multiple terminals are connected and want to read/write to the file system) <br/>
Scalability (hard limit of 10 files, should be dynamic) <br/>
Persistence (files are stored only on RAM, could be written to SD card) <br/>
Advanced features (no directories that would make it similar to a real file storage) <br/>
