#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "socket_mon.h"



struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_socket SEC(".maps");



//the only purpose of this ring buf is to let userspace know
//that data was written to the hashmap, that way userspace can
//poll the ringbuf rather than do some complicated checks
//on the hashmap
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_read SEC(".maps");




//pass_buf is used to get a reference to the buffer
//received on read_enter, this gets used by read exit
//when the buffer has actual data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, u32);
    __type(value, struct read_enter_data_t);
    // __uint(pinning, LIBBPF_PIN_BY_NAME); 
} pass_buf SEC(".maps");


//data_map is used to write data from the 
//pass_buf buffer into a map to be read
//by userspace, basically this gives userspace
//the resulting read data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, u32);
    __type(value, struct read_exit_data_t);
    // __uint(pinning, LIBBPF_PIN_BY_NAME); 
} data_map SEC(".maps");



//to track specific processes to prevent 
//tracking data for every single entrance
//to very common syscalls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, u32);
    __type(value, struct socket_proc_track_struct_t);
    // __uint(pinning, LIBBPF_PIN_BY_NAME); 
} process_map SEC(".maps");


//
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, u32);
    __type(value, struct fd_track_proc_struct_t);
    // __uint(pinning, LIBBPF_PIN_BY_NAME); 
} fd_map SEC(".maps");



SEC("tp/syscalls/sys_enter_socket")
int tp_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    
    struct socket_data_t data = {}; 


    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.domain = (int) BPF_CORE_READ(ctx, args[0]);
    data.type = (int) BPF_CORE_READ(ctx, args[1]);
    data.protocol = (int) BPF_CORE_READ(ctx, args[2]);

    //only track rocesses by this uid, and specific socket domains
    if(data.uid == 490 && (data.domain == AF_INET6 || data.domain == AF_INET)){

        struct socket_proc_track_struct_t proc_to_track = {};

        proc_to_track.pid = data.pid;
        proc_to_track.uid = data.uid;
        proc_to_track.reason = SOCKET_TRACK;
    
        


        uint64_t pid_tgid_key = bpf_get_current_pid_tgid();

        long error = bpf_map_update_elem(&process_map, &pid_tgid_key, &proc_to_track, BPF_ANY);
        bpf_printk("error code add to process_map = %ld", error);


    }


    //send data to buffer to be polled by userspace
    bpf_ringbuf_output(&output_socket, &data, sizeof(data), 0);   

    return 0;
}


SEC("tp/syscalls/sys_exit_socket")
int tp_sys_exit_socket(struct trace_event_raw_sys_enter *ctx) {
    
    uint64_t pid_tgid_key = bpf_get_current_pid_tgid();

    struct socket_proc_track_struct_t *existing_proc_to_track = bpf_map_lookup_elem(&process_map, &pid_tgid_key);

    int fd = (int) BPF_CORE_READ(ctx, args[0]);

    //if invalid fd check if we were tracking the 
    //process and remove it if so...
    if(fd < 0){

        if(existing_proc_to_track != NULL){
            bpf_map_delete_elem(&process_map, &pid_tgid_key);
        }
        return -1;
    }

    

    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    if(uid == 490){

        if(existing_proc_to_track == NULL){
            return 0;
        }

        

        int pid = bpf_get_current_pid_tgid() >> 32;

        struct fd_track_proc_struct_t *proc_with_fd = bpf_map_lookup_elem(&fd_map, &pid);

        if(proc_with_fd == NULL){

            struct fd_track_proc_struct_t new_proc_with_fd = {};
            new_proc_with_fd.pid = pid;
            new_proc_with_fd.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            new_proc_with_fd.fds[0] = fd;
            new_proc_with_fd.fd_count = 1;
            new_proc_with_fd.reason = SOCKET_TRACK;
            long error = bpf_map_update_elem(&fd_map, &pid, &new_proc_with_fd, BPF_ANY);
            bpf_printk("error code add to fd_map first add = %ld", error);

        }else{

            if(proc_with_fd -> fd_count >= MAX_FD_COUNT){
                bpf_printk("ERROR MAX FDS REACHED FOR PROCESS WITH PID = %d", pid);
                return 0;
            }else{
                int new_index = proc_with_fd -> fd_count + 1;
                if(new_index < MAX_FD_COUNT && MAX_FD_COUNT < 5){
                    //seems kind of weird if pid didn't match
                    //so not gonna obsess on that...
                    proc_with_fd -> pid = pid;
                    proc_with_fd -> uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                    proc_with_fd -> fds[new_index] = fd;
                    proc_with_fd -> fd_count = proc_with_fd -> fd_count + 1;
                    proc_with_fd -> reason = SOCKET_TRACK;
                }else{
                    return 0;
                }
            }
            


        }


        


    }


    return 0;
}


SEC("tp/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    

    //use pid_tgid as key for map because the thread
    //is blocked until it returns from the system call
    //so it will work out this way.
    uint64_t pid_tgid_key = bpf_get_current_pid_tgid();

    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    //update data to insert
    struct read_enter_data_t new_read_enter_data = {}; 
    new_read_enter_data.pid = pid_tgid_key >> 32;
    new_read_enter_data.uid = uid;
    new_read_enter_data.num_bytes_desired = (int) BPF_CORE_READ(ctx, args[2]);
    new_read_enter_data.buf_ptr = (void*)BPF_CORE_READ(ctx, args[1]);

    


    struct fd_track_proc_struct_t *tracked_proc_fd = bpf_map_lookup_elem(&fd_map, &new_read_enter_data.pid);



    if(uid == 490 && tracked_proc_fd != NULL){
        


        long error = bpf_map_update_elem(&pass_buf, &pid_tgid_key, &new_read_enter_data, BPF_ANY);
        // bpf_printk("desired bytes sent = %d", new_read_enter_data.num_bytes_desired);
        
    }   

    return 0;
}


SEC("tp/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_enter *ctx) {
    
    //use pid_tgid as key for map because the thread
    //is blocked until it returns from the system call
    //so it will work out this way.
    uint64_t pid_tgid_key = bpf_get_current_pid_tgid();

    int pid = pid_tgid_key >> 32;

    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct fd_track_proc_struct_t *tracked_proc_fd = bpf_map_lookup_elem(&fd_map, &pid);

    if(uid == 490 && tracked_proc_fd != NULL){

        struct read_enter_data_t *existing_read_enter_data = bpf_map_lookup_elem(&pass_buf, &pid_tgid_key);
    
        if(existing_read_enter_data != NULL){

            //this is the return value from read, which is the number of successful
            //bytes read, and so this is how many we still need to write to the 
            //heap map
            int remaining_bytes_to_write = (int) BPF_CORE_READ(ctx, args[0]);

            bpf_printk("desired bytes received = %d", existing_read_enter_data ->num_bytes_desired);

            //if nothing was read just return
            if(remaining_bytes_to_write <= 0){
                return 0;
            }

            //since we can write at most DATA_BUFFER_SIZE
            //it will be either that or less
            int write_amount;

            struct read_exit_data_t exit_dat = {};

            while(remaining_bytes_to_write > 0){

                if(remaining_bytes_to_write < DATA_BUFFER_SIZE){
                    write_amount = DATA_BUFFER_SIZE;
                }else{
                    write_amount = remaining_bytes_to_write;
                }


                bpf_probe_read_user(exit_dat.read_data, write_amount, existing_read_enter_data->buf_ptr);

                bpf_printk("%s \n", exit_dat.read_data);

                remaining_bytes_to_write -= write_amount;

            }


        }

    }
       

    return 0;
}








char LICENSE[] SEC("license") = "Dual BSD/GPL";
