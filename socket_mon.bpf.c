#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "socket_mon.h"

#define DATA_BUFFER_SIZE 256
#define MAX_KEYS 1000

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_socket SEC(".maps");



//the only purpose of this ring buf is to let userspace know
//that data was written to the hashmap, that way userspace can
//poll the ringbuf rather than acquiring spinlocks on the 
//hashamp which would slow everything down, since the ringbuf
//holds no useful it doesn't matter if it gets polled
//the value sent to the ringbuf is the key value
//to read from on the hashmap
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_read SEC(".maps");



//THE FOLLOWING 2 MAPS ARE FIFOs WITH READ AND 
//WRITE POINTERS, AND THEY ARE CIRCULAR SO THAT
//THEY START BACK AT 0 ONCE MAX INDEX IS REACHED...



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


long pass_read_key = 0;
long pass_write_key = 0;
long data_read_key = 0;
long data_write_key = 0;


void update_pass_read_key(){
    //update pass_buf key
    if(pass_read_key + 1 == MAX_KEYS){
        pass_read_key = 0;
    }else{
        pass_read_key += 1;
    }
}

void update_pass_write_key(){
    //update pass_buf key
    if(pass_write_key + 1 == MAX_KEYS){
        pass_write_key = 0;
    }else{
        pass_write_key += 1;
    }
}


void update_data_read_key(){
    //update pass_buf key
    if(data_read_key + 1 == MAX_KEYS){
        data_read_key = 0;
    }else{
        data_read_key += 1;
    }
}

void update_data_write_key(){
    //update pass_buf key
    if(data_write_key + 1 == MAX_KEYS){
        data_write_key = 0;
    }else{
        data_write_key += 1;
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

    //get new data 
    struct bpf_spin_lock new_lock = {};
    struct read_enter_data_t new_read_enter_data = {}; 
    new_read_enter_data.pid = bpf_get_current_pid_tgid() >> 32;
    new_read_enter_data.uid = uid;
    new_read_enter_data.num_bytes = (int) BPF_CORE_READ(ctx, args[2]);
    new_read_enter_data.buf_ptr = (void*)BPF_CORE_READ(ctx, args[1]);
    new_read_enter_data.lock = new_lock;
    new_read_enter_data.can_read = true;
    new_read_enter_data.can_write = false;

    
    if(uid == 490){


        struct  read_enter_data_t *existing_read_enter_data = bpf_map_lookup_elem(&pass_buf, &pass_write_key);

        //first time inserting into map don't need to get spinlock
        if(existing_read_enter_data == NULL){
            
            //insert into the pass map
            long error = bpf_map_update_elem(&pass_buf, &pass_write_key, &new_read_enter_data, BPF_ANY);
            bpf_printk("Error code for pass_buf first insert = %ld\n", error);

            update_pass_write_key();

        //the key exists so need to get spinlock in order to update it
        }else{

            bool done_writing = false;

            //atomically update the value
            while(done_writing == false){
                bpf_spin_lock(&existing_read_enter_data->lock);
                    if(existing_read_enter_data -> can_write){
                        

                        long error = bpf_map_update_elem(&pass_buf, &pass_write_key, &new_read_enter_data, BPF_ANY);
                        bpf_printk("Error code for pass_buf existing update = %ld\n", error);

                        // existing_read_enter_data -> pid = bpf_get_current_pid_tgid() >> 32;
                        // existing_read_enter_data -> uid = uid;
                        // existing_read_enter_data -> num_bytes = (int) BPF_CORE_READ(ctx, args[2]);
                        // existing_read_enter_data -> buf_ptr = (void*)BPF_CORE_READ(ctx, args[1]);
                        // existing_read_enter_data -> can_read = true;
                        // existing_read_enter_data -> can_write = false;

                        update_pass_write_key();

                        done_writing = true;
                    }
                bpf_spin_unlock(&existing_read_enter_data->lock);
            }


        }
        
        
    }   

    return 0;
}


SEC("tp/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_enter *ctx) {
    
    
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if(uid == 490){
       
        //can't do anything until pass_buf has data in the correct index
        bool found_existing_data = false;

        struct read_enter_data_t *existing_read_enter_data;

        while(found_existing_data == false){
            //use read key
            existing_read_enter_data = bpf_map_lookup_elem(&pass_buf, &pass_read_key);

            //we only care if it does exist, 
            if(existing_read_enter_data != NULL){

                

                bool done_reading = false;

                //atomically read the value
                while(done_reading == true){
                    bpf_spin_lock(&existing_read_enter_data->lock);
                        if(existing_read_enter_data -> can_read){
                            

                            //since bytes can only be written 256 at a time, but read likely got
                            //more than that, this needs to be done in increments
                            int remaining_bytes_to_write = existing_read_enter_data -> num_bytes;

                            

                            while(remaining_bytes_to_write > 0){

                                struct bpf_spin_lock new_lock = {};
                                struct read_exit_data_t new_read_exit_data = {}; 

                                int bytes_to_write;

                                //update the read exit data
                                new_read_exit_data.pid = existing_read_enter_data -> pid;
                                new_read_exit_data.uid = existing_read_enter_data -> uid;
                                new_read_exit_data.num_bytes_desired = existing_read_enter_data -> num_bytes;
                                new_read_exit_data.num_bytes_got = (int) BPF_CORE_READ(ctx, args[0]);
                                new_read_exit_data.lock = new_lock;
                                new_read_exit_data.can_read = true;
                                new_read_exit_data.can_write = false;

                                if(remaining_bytes_to_write > DATA_BUFFER_SIZE){
                                    bytes_to_write = DATA_BUFFER_SIZE;
                                    remaining_bytes_to_write -= DATA_BUFFER_SIZE;
                                }else{
                                    bytes_to_write = remaining_bytes_to_write;
                                    remaining_bytes_to_write -= remaining_bytes_to_write;
                                }

                                bpf_probe_read_user(new_read_exit_data.read_data, bytes_to_write, existing_read_enter_data->buf_ptr);

                                
                                struct read_exit_data_t *existing_read_exit_data = bpf_map_lookup_elem(&pass_buf, &data_write_key); 

                                //first time inserting into map don't need to get spinlock
                                if(existing_read_exit_data == NULL){
                                    
                                    //insert into the data map
                                    long error = bpf_map_update_elem(&data_map, &data_write_key, &new_read_exit_data, BPF_ANY);
                                    bpf_printk("Error code for data_map insert = %ld\n", error);


                                //the key exists so need to get spinlock in order to update it
                                }else{

                                    bool done_writing = false;

                                    //atomically update the value
                                    while(done_writing == false){
                                        bpf_spin_lock(&existing_read_exit_data->lock);
                                            if(existing_read_exit_data -> can_write){
                                                long error = bpf_map_update_elem(&pass_buf, &data_write_key, &new_read_exit_data, BPF_ANY);
                                                bpf_printk("Error code for data_map existing update = %ld\n", error);

                                                done_writing = true;
                                            }
                                        bpf_spin_unlock(&existing_read_exit_data->lock);
                                    }


                                }

                                //let user space know there is data in the hashmap
                                //and give them the read key
                                bpf_ringbuf_output(&output_read, &data_read_key, sizeof(data_read_key), 0);
                                update_data_write_key();

                                
                            }

                            //update this after the inner loop, because the multiple
                            //writes to data_map are all from the same read
                            update_pass_read_key();

                            //break the outer while loop
                            done_reading = true;
                        }
                    bpf_spin_unlock(&existing_read_enter_data->lock);
                }


            }
            
        }



    }

       

    return 0;
}





char LICENSE[] SEC("license") = "Dual BSD/GPL";
