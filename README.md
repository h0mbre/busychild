## Busychild
Busychild is a `pstree` like utility with some added functionality built on. Busychild is aimed at getting a better understanding of applications which create numerous child processes. Busychild should allow users to peek into a portion of the IPC being used by the target process and highlight shared file descriptors (sockets (not datagram afaik), pipes) with other processes.

Hopefully the code isn't completely opaque and users are able to modify it to suit their needs. There is a lot of room left for added functionality as I've only chosen to highlight a small subset of the information available about a given process. There are many unexplored process aspects which lend themselves well to being highlighted by the program, such as: shared mapped files, CPU utilization, virtual memory size, process state, etc. These are all available through the wonderful [procfs Crate](https://docs.rs/procfs/0.8.0/procfs/index.html). 

Busychild is in a very early stage, please report any bugs! The code could use a heavy dose of refactoring, but it seems to be in a working state. **I've hardcoded a constant in the code in order to render the process start times as a UTC timestamp correctly, this constant is the `_SC_CLK_TCK` which, when used in conjuction with the process' start time and the OS boot time, can give you a UTC timestamp. This constant is set to 100 on my machine, please check yours in order to get the right result**

Currently, Busychild displays the following process information:
+ pid and process name,
+ parent pid,
+ level (a recursion level as compared to the greatest parent process),
+ owner (uid of process owner),
+ start time,
+ thread count,
+ command line,
+ socket inodes and the pids with which this inode is shared, and
+ pipe inodes and the pids with which this inode is shared

## Usage

### Default Mode
The default mode will take a target pid,  `sysargv[1]`, and will recursively map out both parents of the pid and children of the pid. This mode will then color-code each discovered process node and arrange them in a `pstree`-like hiearchy.

Default mode can be utilized as follows: 
+ `./busychild <pid>`
+ `./busychild 1`

### Quiet Mode
Quiet mode is similar to Default Mode; however, only the target pid information will be printed.

Quiet mode can be utilized as follows:
+ `./busychild <pid> -q`
+ `./busychild <pid> --quiet`

### Socket Mode
Socket mode will look up a socket inode and try to find all of the processes which have an open file descriptor to this socket.

Socket mode can be utilized as follows:
+ `./busychild -s <socket_number>`
+ `./busychild --socket <socket_number>`

### Pipe Mode
Pipe mode will look up a socket inode and try to find all of the processes which have an open file descriptor to this socket.

Pipe mode can be utilized as follows:
+ `./busychild -p <socket_number>`
+ `./busychild --pipe <socket_number>`
