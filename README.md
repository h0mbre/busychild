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
```
OPTIONS:
	-q, --quiet	only print information for target pid
	-s, --socket	print information for specific socket inode
	-p, --pipe	print information for specific pipe inode
	-h, --help	print this!
EXAMPLES:
	usage: ./busychild <pid> <options>
	usage: ./busychild 1337
	usage: ./busychild 1337 -q
	usage: ./busychild <inode switch> <inode number>
	usage: ./busychild -s 1337
	usage: ./busychild -p 1337
```

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

## Output
Here is some sample output for default mode with pid `121486`. For color coding output, see this image: 
```
pid/proc: 1/systemd, ppid: 0, level, 0
owner: 0, start: 2020-08-16 00:05:39 UTC, threads: 1
cmd: /sbin/initautonoprompt
│
│
└──pid/proc: 121403/code, ppid: 1, level, 1
   owner: 1000, start: 2020-09-01 22:11:17 UTC, threads: 27
   cmd: /usr/share/code/code --no-sandbox --unity-launch
   socket:[2731821]: 121407/code, 121450/code, 121486/code, 121504/code, 121622/code
   socket:[53569]: 121407, 121431, 121438, 121450, 121504, 121622, 126855, 126899, 126949, 126987, 2352
   socket:[53570]: 121407, 121431, 121438, 121450, 121504, 121622, 126855, 126899, 126949, 126987, 2352
   │
   │
   └──pid/proc: 121450/code, ppid: 121403, level, 2
      owner: 1000, start: 2020-09-01 22:11:18 UTC, threads: 19
      cmd: /usr/share/code/code --type=renderer --disable-color-correct-rendering --no-sand...<snip>
      socket:[2731821]: 121403/code, 121407/code, 121486/code, 121504/code, 121622/code
      socket:[2731926]: 121486/code, 121504/code
      socket:[2732789]: 121486/code, 121504/code
      socket:[2732811]: 121486/code, 121504/code, 121540/sh, 121541/rls
      socket:[53569]: 121403, 121407, 121431, 121438, 121504, 121622, 126855, 126899, 126949, 126987, 2352
      socket:[53570]: 121403, 121407, 121431, 121438, 121504, 121622, 126855, 126899, 126949, 126987, 2352
      │
      │
      └──pid/proc: 121486/code, ppid: 121450, level, 3
         owner: 1000, start: 2020-09-01 22:11:19 UTC, threads: 18
         cmd: /usr/share/code/code--inspect-port=0/usr/share/code/resources/app/out/bootstra...<snip>
         socket:[2731821]: 121403/code, 121407/code, 121450/code, 121504/code, 121622/code
         socket:[2731926]: 121450/code, 121504/code
         socket:[2732789]: 121450/code, 121504/code
         socket:[2732811]: 121450/code, 121504/code, 121540/sh, 121541/rls
         │
         │
         └──pid/proc: 121540/sh, ppid: 121486, level, 4
            owner: 1000, start: 2020-09-01 22:11:21 UTC, threads: 1
            cmd: /bin/sh-crustup run stable-x86_64-unknown-linux-gnu rls
            socket:[2732811]: 121450/code, 121486/code, 121504/code, 121541/rls
            socket:[2733175]: 121541/rls
            socket:[2733177]: 121541/rls
            socket:[2733179]: 121541/rls
            │
            │
            └──pid/proc: 121541/rls, ppid: 121540, level, 5
               owner: 1000, start: 2020-09-01 22:11:21 UTC, threads: 5
               cmd: /home/h0mbre/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rls
               socket:[2732811]: 121450/code, 121486/code, 121504/code, 121540/sh
               socket:[2733175]: 121540/sh
               socket:[2733177]: 121540/sh
               socket:[2733179]: 121540/sh
```

<p align="left">
  <img src=/default.PNG></img>
</p>
