#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "socket_mon.h"


const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "do_execve";
const char fentry_msg[16] = "fentry_execve";
const char tp_msg[16] = "tp_execve";
const char tp_msg2[16] = "tp_openat";
const char tp_msg3[16] = "pseudocat";
const char tp_msg4[16] = "read";
const char test_msg[16] = "test_message";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_socket SEC(".maps");



//the only purpose of this ring buf is to let userspace know
//that data was written to the hashmap, that way userspace can
//poll the ringbuf rather than acquiring spinlocks on the 
//hashamp which would slow everything down, since the ringbuf
//holds no useful it doesn't matter if it gets polled
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_read SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, u32);
    __type(value, void*);
    // __uint(pinning, LIBBPF_PIN_BY_NAME); 
} pass_buf SEC(".maps");


#define MIN(a,b) (((a)<(b))?(a):(b))



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, u32);
    __type(value, struct data_buffer_t);
    // __uint(pinning, LIBBPF_PIN_BY_NAME); 
} data_map SEC(".maps");


long pass_key = 0;
long data_key = 0;


void update_pass_key(){
    //update pass_buf key
    if(pass_key + 1 == MAX_KEYS){
        pass_key = 0;
    }else{
        pass_key += 1;
    }
}




SEC("tp/syscalls/sys_enter_socket")
int tp_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    
    struct socket_data_t data = {}; 


    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.domain = (int) BPF_CORE_READ(ctx, args[0]);
    data.type = (int) BPF_CORE_READ(ctx, args[1]);
    data.protocol = (int) BPF_CORE_READ(ctx, args[2]);


    //send data to buffer to be polled by userspace
    bpf_ringbuf_output(&output_socket, &data, sizeof(data), 0);   

    return 0;
}


SEC("tp/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    if(uid == 490){

        //first check if the given key exists
        struct  read_enter_data_t *existing_value = bpf_map_lookup_elem(&pass_buf, &pass_key);

        //first time inserting into map
        if(existing_value == NULL){
            
            
            struct bpf_spin_lock new_lock = {};
            struct read_enter_data_t new_insert = {}; 

            new_insert.pid = bpf_get_current_pid_tgid() >> 32;
            new_insert.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            new_insert.num_bytes = (int) BPF_CORE_READ(ctx, args[2]);
            new_insert.buf_ptr = (void*)BPF_CORE_READ(ctx, args[1]);
            new_insert.lock = new_lock;
            new_insert.can_write = false;


            //insert into the pass map
            long error = bpf_map_update_elem(&pass_buf, &pass_key, &new_insert, BPF_ANY);
            bpf_printk("Error code for pass_buf = %ld\n", error);

            update_pass_key();

        //the key exists so need to get spinlock in order to update it
        }else{

            bool done_writing = false;

            //atomically update the
            while(done_writing == false){
                bpf_spin_lock(&existing_value->lock);
                    if(existing_value -> can_write){
                        existing_value -> pid = bpf_get_current_pid_tgid() >> 32;
                        existing_value -> uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                        existing_value -> num_bytes = (int) BPF_CORE_READ(ctx, args[2]);
                        existing_value -> buf_ptr = (void*)BPF_CORE_READ(ctx, args[1]);
                        existing_value -> can_write = false;

                        update_pass_key();

                        done_writing = true;
                    }
                bpf_spin_unlock(&existing_value->lock);
            }


        }
        
        
    }   

    return 0;
}


SEC("tp/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_enter *ctx) {
    
    struct exit_read_data_t data = {}; 

  

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.num_bytes = (int) BPF_CORE_READ(ctx, args[0]);


    int zero = 0;

    char *map_buf;
    void **ubuf;
    unsigned long min;


    if(data.uid == 490){
       

        ubuf = bpf_map_lookup_elem(&pass_buf, &zero);
        if (!ubuf){
                bpf_printk("failure couldn't lookup elem from pass_buf");
                return 0;
        }
        if (data.num_bytes <= 0){
                bpf_printk("failure 1");
                return 0;
        }
        map_buf = bpf_map_lookup_elem(&data_map, &zero);
        if (!map_buf) {
                bpf_printk("failure 2");
                return 0;
        }
        // min = MIN(data.num_bytes, DATA_BUFFER_SIZE);
        // min &= 0xffff;
        if(data.num_bytes < 256){
            min = data.num_bytes;
        }else{
            min = 256;
        }
        
        if (bpf_probe_read_user(map_buf, min, *ubuf)) {
                bpf_printk("failure 3");
                return 0;
        }else{
            bpf_printk("val is %s", map_buf);
        }
        
    }

    //let user space know there is a write to the hashmap
    int done = 1;
    bpf_ringbuf_output(&output_read, &done, sizeof(done), 0);   

    return 0;
}





char LICENSE[] SEC("license") = "Dual BSD/GPL";
