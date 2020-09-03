use procfs::process::{all_processes, Process};
use chrono::{TimeZone, Utc};
use std::collections::HashMap;
use std::{env, fs};
use glob::glob;

const _SC_CLK_TCK:u64 = 100;

#[derive(Clone)]
pub struct CompleteProc {
    proc_blob: Process,
    level:     i32,
    relation:  String,
    cmdline:   String,
    tasks:     i64,
    start:     String,
    sockets:   Vec<(String, Vec<String>)>,
    pipes:     Vec<(String, Vec<String>)>,
}

fn vet_pid(pid: &i32, map: &HashMap<i32, Process>) -> bool {
    // make sure we have this pid in our hashmap
    match map.get(pid) {
        Some(_) => true,
        None    => false,
    }
}

fn build_process_lookup() -> HashMap<i32, Process> {
    let mut lookup = HashMap::new();

    for prc in all_processes().unwrap() {
        lookup.insert(prc.pid, prc);
    }

    lookup
}

fn build_process_tree() -> HashMap<i32, Vec<Process>> {
    let mut tree: HashMap<i32, Vec<Process>> = HashMap::new();

    // iterate through all the processes on system
    // children is going to be a vector of children pids for a given ppid
    // if there is already an entry in the hashmap, aka a vector,
    // we'll add our process to it, if theres not an entry,
    // aka, there are now ppids established for this pid, we'll make a new vector
    for prc in all_processes().unwrap() {
        let children = tree.entry(prc.stat.ppid).or_insert_with(Vec::new);
        children.push(prc);
    }

    tree
}

fn pstree(me: &i32, process_tree: &HashMap<i32, Vec<Process>>, 
    process_lookup: &HashMap<i32, Process>, level: i32) -> Vec<(i32, Process)> {
    let mut processes = vec![];

    // look up the value of the key 'me', this is a pid
    // we are retrieving a Process
    // add the Process and the level to this vector
    let process = process_lookup[me].to_owned();
    processes.push((level, process));

    // if process tree doesnt have our pid, we are done
    if !process_tree.contains_key(me) {
        return processes
    }

    // if it does have our pid, then we have children we need to know about
    let children = process_tree[me].to_owned();

    // for all the children we discovered, recursively find the children of those children
    // but each time, increase the level
    // this way we create a hiearchy of parents and their children recursively
    for child in children {
        processes.extend(pstree(&child.pid, &process_tree, &process_lookup, level + 1));
    }

    processes
}

fn build_inodemaps() -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    // we're going to creat two hashmaps here,
    // one hashmap is going to contain all the socket inodes and the pids that have
    // fds for those inodes, the other hashmap is the same but for pipe inodes
    let mut socket_inodes: HashMap<String, Vec<String>> = HashMap::new();
    let mut pipe_inodes: HashMap<String, Vec<String>> = HashMap::new();

    // iterate through all the proc/pid/fds and read the symlinks
    let mut entries: Vec<String> = vec![];
    for entry in glob("/proc/[0-9]*/fd/*").unwrap() {
        if let Ok(entry) = entry {
            entries.push(entry.display().to_string());
        }
    }

    // if a symlink has 'socket' or 'pipe' in it, lets look it up 
    // in our HashMaps and if its not there, lets add it. if it is there,
    // let's add our pid to the vector of pids that have the inode as an fd
    for item in &entries {
        let pid_iter: Vec<&str> = item.split('/').collect();
        let pid = pid_iter[2].to_string();
        let link = fs::read_link(item);
        match link {
            Ok(path) => {
                let formatted_link = path.display().to_string();
                if formatted_link.contains("socket") {
                    match socket_inodes.get_mut(&formatted_link) {
                        Some(pids) => pids.push(pid),
                        None       => {
                            socket_inodes.insert(formatted_link, vec![pid]);
                        }
                    }
                }
                else if formatted_link.contains("pipe") {
                    match pipe_inodes.get_mut(&formatted_link) {
                        Some(pids) => pids.push(pid),
                        None       => {
                            pipe_inodes.insert(formatted_link, vec![pid]);
                        }
                    }
                }
            }
            Err(_e) => (),
        }
    }

    // return a tuple of both hashmaps
    (socket_inodes, pipe_inodes)
}

fn collect_parents(pid: &i32, map: &HashMap<i32, Process>) -> Vec<Process> {
    // i believe here what im doing is take the reference we were given
    // as a function argument and what im doing is taking that value and creating
    // a new variable? not 100% on this
    let mut pid = *pid;
    let mut parents: Vec<Process> = vec![];
    
    // lookup the ppid of our current pid, if we find something
    // then the parent becomes the pid and we look up their ppid
    // until we run out of parents
    loop {
        let tmp_process = match map.get(&pid) {
            Some(process) => process,
            None          => break,
        };

        parents.push(tmp_process.clone());
        pid = tmp_process.stat.ppid;
    }

    parents.reverse();
    parents
}

// retrieves cmdline info for process
fn get_cmd(pid: &i32) -> String {
    let error = "unable to parse cmdline".to_string();
    let result = fs::read_to_string(format!("/proc/{}/cmdline", pid));
    let mut cmd = match result {
        Ok(cmd) => cmd,
        Err(_e) => error,
    };

    if cmd.len() > 80 {
        cmd.truncate(80);
        cmd.push_str("...<snip>");
    }

    if cmd.is_empty() {
        cmd = "-- none --".to_string();
    }

    cmd
} 

// _SC_CLK_TCK is of course hardcoded as a define
// this just simply gets the machine boot time and then
// adds in the start time and converts it to a UTC timestamp
fn get_start(start_time: u64) -> String {
    let start = (start_time / _SC_CLK_TCK) as i64;
    let boot_info = fs::read_to_string("/proc/stat").unwrap();
    
    let boot_time_str: Vec<&str> = boot_info.lines()
        .filter(|x| x.contains("btime"))
        .collect();
    
    let boot_time = i64::from_str_radix(&boot_time_str[0]
        .replace("btime ", ""), 10).unwrap();
    
    let dt = Utc.timestamp(start + boot_time, 0);
    dt.to_string()
}

fn lookup_inodes(pid: &i32) -> (Vec<String>, Vec<String>) {
    let mut sockets: Vec<String> = vec![];
    let mut pipes:   Vec<String> = vec![];

    // get all file descriptor paths for our pid
    let lookup = format!("/proc/{}/fd/*", pid);
    let mut entries: Vec<String> = vec![];
    for entry in glob(&lookup).unwrap() {
        if let Ok(entry) = entry {
            entries.push(entry.display().to_string());
        }
    }

    // look through the fd paths and read the sym links
    // if we get pipes or sockets, add them to our arrays
    for item in &entries {
        let link = fs::read_link(item);
        match link {
            Ok(path) => {
                let formatted_link = path.display()
                    .to_string();
                if formatted_link.contains("socket") {
                    sockets.push(formatted_link);
                }
                else if formatted_link.contains("pipe") {
                    pipes.push(formatted_link);
                }
            }
            Err(_e) => (),
        }
    }

    sockets.sort_unstable();
    sockets.dedup();
    pipes.sort_unstable();
    pipes.dedup();
    (sockets, pipes)
}

fn lookup_procname(lookup_table: &HashMap<i32, Process>, pids: &[String]) -> Vec<String> {
    let mut returned_procnames: Vec<String> = vec![];
    
    // we want to marry up a pid with a process name; however,
    // if the list of pids is too long, we just dont retrieve names since
    // that might ruin the formatting
    if pids.len() < 8 {
        for item in pids.iter() {
            if let Some(proc_name) = lookup_table.get(&item.parse::<i32>().unwrap()) {
                returned_procnames.push(format!("{}/{}", &item.parse::<i32>().unwrap(),
                    proc_name.stat.comm.clone()));
            }
        }
        returned_procnames
    } else {
        pids.to_owned()
    }
}

fn lookup_procname_reckless(lookup_table: &HashMap<i32, Process>, pids: &[String]) -> Vec<String> {
    let mut returned_procnames: Vec<String> = vec![];
    
    // we want to marry up a pid with a process name; however,
    
    for item in pids.iter() {
        if let Some(proc_name) = lookup_table.get(&item.parse::<i32>().unwrap()) {
            returned_procnames.push(format!("{}/{}", &item.parse::<i32>().unwrap(),
                proc_name.stat.comm.clone()));
        }
    }
    returned_procnames
}


fn match_inodes(ppid: &i32,
    inodes: Vec<String>, 
    inodemap: &HashMap<String, Vec<String>>,
    lookup_table: &HashMap<i32, Process>) -> Vec<(String, Vec<String>)> {
    
    // take our pid's inodes and search for other pids that have the same
    // ones open
    let mut matched_inodes: Vec<(String, Vec<String>)> = vec![]; 
    for item in &inodes {
        if let Some(shared) = inodemap.get(item) {
            let mut clone = shared.clone();
            clone.retain(|n| n != &ppid.to_string());
            clone.sort_unstable();
            clone.dedup();
            if !clone.is_empty() { 
                let proc_names = lookup_procname(lookup_table, &clone);
                matched_inodes.push((item.to_string(), proc_names));
            }
        }
    }
    matched_inodes
}

fn finalize_parents(parents: Vec<Process>,
    socketmap: &HashMap<String, Vec<String>>,
    pipemap: &HashMap<String, Vec<String>>,
    lookup_table: &HashMap<i32, Process>) -> Vec<CompleteProc> {

    let mut level = 0;
    let mut final_parents: Vec<CompleteProc> = vec![];

    // just making some CompleProc structs based on the Process
    // members and some one-off functions I made for things I didn't
    // like or couldn't find in the Process 
    for x in 0..parents.len() {
        let relation: String;
        // last one here is the target
        if x != parents.len() - 1 {
            relation = "Parent".to_string();
        } else {
            relation = "Target".to_string();
        }

        // kind of surprised this isnt in the Process.stat ?
        let cmd = get_cmd(&parents[x].stat.pid);
        let tasks = parents[x].stat.num_threads;
        let start = get_start(parents[x].stat.starttime);
        
        let pid = parents[x].stat.pid;

        let inodes = lookup_inodes(&parents[x].stat.pid);
        let sockets = inodes.0;
        let pipes = inodes.1;

        let matched_sockets = match_inodes(&pid, sockets, socketmap, lookup_table);
        let matched_pipes = match_inodes(&pid, pipes, pipemap, lookup_table);

        let tmp_struct = CompleteProc {
            proc_blob: parents[x].clone(),
            level,
            relation,
            cmdline:   cmd,
            tasks,
            start,
            sockets:   matched_sockets,
            pipes:     matched_pipes,
        };

        final_parents.push(tmp_struct);
        level += 1;
    }

    final_parents
}

fn finalize_children(children: Vec<(i32, Process)>,
    socketmap: &HashMap<String, Vec<String>>,
    pipemap: &HashMap<String, Vec<String>>,
    lookup_table: &HashMap<i32, Process>) -> Vec<CompleteProc> {
    let mut final_children: Vec<CompleteProc> = vec![];

    // skipping the first entry because thats a repeat of our Target
    // just assembling a CompleteProc based on some diff functions and 
    // the already existing elements of the Process and then pushing
    // that into a vector of children
    for item in children.iter().skip(1) {
        let cmd = get_cmd(&item.1.stat.pid);
        let tasks = item.1.stat.num_threads;
        let start = get_start(item.1.stat.starttime);

        let pid = item.1.stat.pid;

        let inodes = lookup_inodes(&item.1.stat.pid);
        let sockets = inodes.0;
        let pipes = inodes.1;

        let matched_sockets = match_inodes(&pid, sockets, socketmap, lookup_table); 
        let matched_pipes = match_inodes(&pid, pipes, pipemap, lookup_table);

        let tmp_struct = CompleteProc {
            proc_blob: item.1.clone(),
            level:     item.0,
            relation:  "Child".to_string(),
            cmdline:   cmd,
            tasks,
            start,
            sockets:   matched_sockets,
            pipes:     matched_pipes,
        };

        final_children.push(tmp_struct);
    }

    final_children
}

fn default_display(input: Vec<CompleteProc>) {

    let mut max_level = 0;
    for item in &input{
        if item.level > max_level {
            max_level = item.level;
        }
    }

    let mut body_spacers:        Vec<String> = vec![];
    let mut bro_head_spacers:    Vec<String> = vec![];
    let mut parent_head_spacers: Vec<String> = vec![];
    
    for x in 0..max_level {
        // the spacer to be used on just the text body of each node
        body_spacers.push("   ".repeat(x as usize + 1).to_string());

        // the spacer to be used on the head if the next node is a brother
        bro_head_spacers.push("   ".repeat(x as usize + 1).to_string());

        // the spacer to be used on the head if the next node is a child
        let mut tmp_head = "   ".repeat(x as usize).to_string();
        tmp_head.push_str("└──");
        parent_head_spacers.push(tmp_head);

    }
    
    println!("\nkey: {}, {}, {}\n",
        format!("\x1B[1;35m{}\x1B[0m", "Parent"),
        format!("\x1B[1;36m{}\x1B[0m", "Target"),
        format!("\x1B[1;33m{}\x1B[0m", "Child"));

    for x in 0..input.len() {
        // figure out the level of the next node so we can draw
        let next_level = if x != input.len() - 1 {
            input[x + 1].level
        } else {
            0
        };

        // compare the next node level to us so we can draw
        let next_relation = if next_level == 0 {
            "end"
        } else if next_level > input[x].level {
            "child"
        } else if next_level == input[x].level {
            "brother"
        } else {
            "parent"
        };

        // figure out the level of the previous node so we can draw
        let prev_level = if x != 0 {
            input[x - 1].level
        } else {
            0
        };

        // compare the previous node level to us so we can draw
        let prev_relation = if prev_level == 0 {
            "end"
        } else if prev_level > input[x].level {
            "child"
        } else if prev_level == input[x].level {
            "brother"
        } else {
            "parent"
        };

        // spacing a function of level + the chars needed for tree
        let level = input[x].level as usize - 1;

        // these are the chars that will be placed on the first line of a node
        let mut head_space = match prev_relation {
            "brother" => bro_head_spacers[level].clone(),
            "end"     => "└──".to_string(),
            "parent"  => parent_head_spacers[level].clone(),
            "child"   => bro_head_spacers[level].clone(),
            _ => panic!(),
        };

        // these will be placed on every subsequent line of a node
        let mut body_space: String;
        match prev_relation {
            "brother" => {
                body_space = body_spacers[level].clone();
            }
            "end"     => {
                body_space = body_spacers[0].clone();
            }
            "parent"  => {
                body_space = body_spacers[level].clone();
            }
            "child"   => {
                body_space = body_spacers[level].clone();
            }
            _ => panic!(),
        };

        // this is the last line of a node
        let mut end_space: String;
        if next_relation == "child" || next_relation == "brother" {
            end_space = "   ".repeat(level + 1).to_string();
            end_space.push_str("│");
        } else {
            end_space = "".to_string();
        }
        
        if x == 0 {
            head_space = "".to_string();
            body_space = "".to_string();
            end_space = "│".to_string();
        }

        match input[x].relation.as_str() {          
            "Parent" => {
                macro_rules! color_print {() => ("\x1B[1;35m{}\x1B[0m")};
                // pid/proc 
                println!("{}{}: {}/{}, {}: {}, {}, {}", head_space, 
                    format!(color_print!(), "pid/proc"),
                    input[x].proc_blob.stat.pid,
                    input[x].proc_blob.stat.comm,
                    format!(color_print!(), "ppid"),
                    input[x].proc_blob.stat.ppid,
                    format!(color_print!(), "level"),
                    input[x].level);

                println!("{}{}: {}, {}: {}, {}: {}", body_space,
                    format!(color_print!(), "owner"),
                    input[x].proc_blob.owner,
                    format!(color_print!(), "start"),
                    input[x].start,
                    format!(color_print!(), "threads"),
                    input[x].tasks);

                println!("{}{}: {}", body_space,
                    format!(color_print!(), "cmd"),
                    input[x].cmdline);

                for y in 0..input[x].sockets.len() {
                    print!("{}{}: ", body_space,
                    format!(color_print!(), input[x].sockets[y].0));
                    for z in 0..input[x].sockets[y].1.len() {
                        if z != input[x].sockets[y].1.len() - 1 {
                            print!("{}, ", input[x].sockets[y].1[z]);
                        } else {
                            print!("{}", input[x].sockets[y].1[z]);
                        }
                    }
                    println!();
                }

                for y in 0..input[x].pipes.len() {
                    print!("{}{}: ", body_space,
                    format!(color_print!(), input[x].pipes[y].0));
                    for z in 0..input[x].pipes[y].1.len() {
                        if z != input[x].pipes[y].1.len() - 1 {
                            print!("{}, ", input[x].pipes[y].1[z]);
                        } else {
                            print!("{}", input[x].pipes[y].1[z]);
                        }
                    }
                    println!();
                }
                
            }
            "Target" => {
                macro_rules! color_print {() => ("\x1B[1;36m{}\x1B[0m")};
                println!("{}{}: {}/{}, {}: {}, {}, {}", head_space, 
                    format!(color_print!(), "pid/proc"),
                    input[x].proc_blob.stat.pid,
                    input[x].proc_blob.stat.comm,
                    format!(color_print!(), "ppid"),
                    input[x].proc_blob.stat.ppid,
                    format!(color_print!(), "level"),
                    input[x].level);

                println!("{}{}: {}, {}: {}, {}: {}", body_space,
                    format!(color_print!(), "owner"),
                    input[x].proc_blob.owner,
                    format!(color_print!(), "start"),
                    input[x].start,
                    format!(color_print!(), "threads"),
                    input[x].tasks);

                println!("{}{}: {}", body_space,
                    format!(color_print!(), "cmd"),
                    input[x].cmdline);

                for y in 0..input[x].sockets.len() {
                    print!("{}{}: ", body_space,
                    format!(color_print!(), input[x].sockets[y].0));
                    for z in 0..input[x].sockets[y].1.len() {
                        if z != input[x].sockets[y].1.len() - 1 {
                            print!("{}, ", input[x].sockets[y].1[z]);
                        } else {
                            print!("{}", input[x].sockets[y].1[z]);
                        }
                    }
                    println!();
                }

                for y in 0..input[x].pipes.len() {
                    print!("{}{}: ", body_space,
                    format!(color_print!(), input[x].pipes[y].0));
                    for z in 0..input[x].pipes[y].1.len() {
                        if z != input[x].pipes[y].1.len() - 1 {
                            print!("{}, ", input[x].pipes[y].1[z]);
                        } else {
                            print!("{}", input[x].pipes[y].1[z]);
                        }
                    }
                    println!();
                }
            }
            "Child"  => {
                macro_rules! color_print {() => ("\x1B[1;33m{}\x1B[0m")};

                println!("{}{}: {}/{}, {}: {}, {}, {}", head_space, 
                    format!(color_print!(), "pid/proc"),
                    input[x].proc_blob.stat.pid,
                    input[x].proc_blob.stat.comm,
                    format!(color_print!(), "ppid"),
                    input[x].proc_blob.stat.ppid,
                    format!(color_print!(), "level"),
                    input[x].level);

                println!("{}{}: {}, {}: {}, {}: {}", body_space,
                    format!(color_print!(), "owner"),
                    input[x].proc_blob.owner,
                    format!(color_print!(), "start"),
                    input[x].start,
                    format!(color_print!(), "threads"),
                    input[x].tasks);

                println!("{}{}: {}", body_space,
                    format!(color_print!(), "cmd"),
                    input[x].cmdline);

                for y in 0..input[x].sockets.len() {
                    print!("{}{}: ", body_space,
                    format!(color_print!(), input[x].sockets[y].0));
                    for z in 0..input[x].sockets[y].1.len() {
                        if z != input[x].sockets[y].1.len() - 1 {
                            print!("{}, ", input[x].sockets[y].1[z]);
                        } else {
                            print!("{}", input[x].sockets[y].1[z]);
                        }
                    }
                    println!();
                }

                for y in 0..input[x].pipes.len() {
                    print!("{}{}: ", body_space,
                    format!(color_print!(), input[x].pipes[y].0));
                    for z in 0..input[x].pipes[y].1.len() {
                        if z != input[x].pipes[y].1.len() - 1 {
                            print!("{}, ", input[x].pipes[y].1[z]);
                        } else {
                            print!("{}", input[x].pipes[y].1[z]);
                        }
                    }
                    println!();
                }
            }
            _        => panic!()
        }
        println!("{}\n{}", end_space, end_space);
    }
}

fn quiet_display(input: Vec<CompleteProc>) {
    println!();
    for item in &input {
        if item.relation == "Target".to_string() {
        macro_rules! color_print {() => ("\x1B[1;36m{}\x1B[0m")};
            println!("{}: {}/{}, {}: {}", 
                format!(color_print!(), "pid/proc"),
                item.proc_blob.stat.pid,
                item.proc_blob.stat.comm,
                format!(color_print!(), "ppid"),
                item.proc_blob.stat.ppid);

            println!("{}: {}, {}: {}, {}: {}",
                format!(color_print!(), "owner"),
                item.proc_blob.owner,
                format!(color_print!(), "start"),
                item.start,
                format!(color_print!(), "threads"),
                item.tasks);

            println!("{}: {}",
                format!(color_print!(), "cmd"),
                item.cmdline);

            for y in 0..item.sockets.len() {
                print!("{}: ",
                format!(color_print!(), item.sockets[y].0));
                for z in 0..item.sockets[y].1.len() {
                    if z != item.sockets[y].1.len() - 1 {
                        print!("{}, ", item.sockets[y].1[z]);
                    } else {
                        print!("{}", item.sockets[y].1[z]);
                    }
                }
                println!();
            }

            for y in 0..item.pipes.len() {
                print!("{}: ",
                format!(color_print!(), item.pipes[y].0));
                for z in 0..item.pipes[y].1.len() {
                    if z != item.pipes[y].1.len() - 1 {
                        print!("{}, ", item.pipes[y].1[z]);
                    } else {
                        print!("{}", item.pipes[y].1[z]);
                    }
                }
                println!();
            }
        }
    }
    println!();
}


fn normal_routine(kind: &str, args: Vec<String>) {

    // make sure the PID is a valid i32
    let pid: i32 = match args[1].parse() {
        Ok(n) => {
            n
        }
        Err(_) => {
            println!("\nunable to parse pid: {}\n", args[1]);
            return;
        }
    };

    // build our hashmap of pid, Process
    let lookup_table = build_process_lookup();
        
    // make sure the PID exists
    if !vet_pid(&pid, &lookup_table) {
        println!("\npid: {} doesn't exist\n", pid);
        return;
    }
    
    // build our hashmap of ppid, Vec<children>
    let process_table = build_process_tree();
    
    // this will return a tuple of two hashmaps
    // one hashmap for sockets, one for pipes
    // each has entries like: inode, Vec<pids>
    let tuple_maps = build_inodemaps();

    let socketmap = tuple_maps.0;
    let pipemap   = tuple_maps.1;
    
    // collect parents of the pid
    // returns vector of Processes, target pid included
    // order will be from low to high
    let parents = collect_parents(&pid, &lookup_table);
    
    // create CompleteProcs out of each entry in parents
    // including the target pid
    let mut final_parents = finalize_parents(parents, &socketmap, &pipemap, &lookup_table);

    // establish the level of our target pid, the last in this vector
    let mut level: i32 = 0;
    if !final_parents.is_empty() {
        level = final_parents[final_parents.len() - 1].level;
    }

    // recursively find all children of our target pid and their children
    let children = pstree(&pid, &process_table, &lookup_table, level);

    // transform all child nodes into CompleteProcs
    let mut final_children = finalize_children(children, &socketmap, &pipemap, &lookup_table);

    // make final node vector
    final_parents.append(&mut final_children);

    if kind == "default" {
        default_display(final_parents);
    } else {
        quiet_display(final_parents);
    }
}

fn socket_routine(args: Vec<String>) {
    let socket_num: i32 = match args[2].parse() {
        Ok(n) => {
            n
        }
        Err(_) => {
            println!("\nunable to parse socket: {}\n", args[2]);
            return;
        }
    };
    let socket = format!("socket:[{}]", socket_num);

    let maps = build_inodemaps();
    let sockets = maps.0;

    let result = sockets.get(&socket);
    match result {
        Some(pids) => {
            let lookup = build_process_lookup();
            let names = lookup_procname_reckless(&lookup, pids);
            println!("\n{}\n", format!("\x1B[1;36m{}\x1B[0m shared by:", socket));
            for item in &names {
                println!("  - {}", item);
            }
            println!();
        }
        None      => {
            println!("\nNo matches for: {}\n", 
               format!("\x1B[1;36m{}\x1B[0m", socket));
        }
    }
}

fn pipe_routine(args: Vec<String>) {
    let pipe_num: i32 = match args[2].parse() {
        Ok(n) => {
            n
        }
        Err(_) => {
            println!("\nunable to parse pipe: {}\n", args[2]);
            return;
        }
    };
    let pipe = format!("pipe:[{}]", pipe_num);

    let maps = build_inodemaps();
    let pipes = maps.1;

    let result = pipes.get(&pipe);
    match result {
        Some(pids) => {
            let lookup = build_process_lookup();
            let names = lookup_procname_reckless(&lookup, pids);
            println!("\n{}\n", format!("\x1B[1;36m{}\x1B[0m shared by:", pipe));
            for item in &names {
                println!("  - {}", item);
            }
            println!();
        }
        None      => {
            println!("\nNo matches for: {}\n", 
               format!("\x1B[1;36m{}\x1B[0m", pipe));
        }
    }
}

fn parse_args(args: Vec<String>) {
    if args[1] == "-s" || args[1] == "--socket" {
        socket_routine(args);
    } else if args[1] == "-p" || args[1] == "--pipe" {
        pipe_routine(args);
    } else if args[2] == "-q" || args[2] == "--quiet" {
        normal_routine("quiet", args);
    } else {
        help();
    }
}

fn help() {
    println!("OPTIONS:");
    println!("\t-q, --quiet\tonly print information for target pid");
    println!("\t-s, --socket\tprint information for specific socket inode");
    println!("\t-p, --pipe\tprint information for specific pipe inode");
    println!("\t-h, --help\tprint this!");
    println!("EXAMPLES:");
    println!("\tusage: ./busychild <pid> <options>");
    println!("\tusage: ./busychild 1337");
    println!("\tusage: ./busychild 1337 -q");
    println!("\tusage: ./busychild <inode switch> <inode number>");
    println!("\tusage: ./busychild -s 1337");
    println!("\tusage: ./busychild -p 1337");
    return;
}

fn main() {
    // collect CLI args
    let args: Vec<String> = env::args().collect();

    match args.len() {
        0 => help(),
        1 => help(),
        2 => {
            normal_routine("default", args);
        }
        3 => {
            parse_args(args);
        }
        _ => help(),        
    }    
}
