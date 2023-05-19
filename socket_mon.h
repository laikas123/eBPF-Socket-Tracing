#define DATA_BUFFER_SIZE 256
#define MAX_KEYS 1000

struct socket_data_t {
   int pid;
   int uid;
   int domain;
   int type;
   int protocol;
};


struct read_data_t {
   int pid;
   int uid;
   int num_bytes;
   void* buf_ptr;
};

struct exit_read_data_t {
   int pid;
   int uid;
   int num_bytes;
};


struct read_enter_data_t {
   struct bpf_spin_lock lock;
   int pid;
   int uid;
   int num_bytes;
   void* buf_ptr;
   bool can_write;
};


struct data_buffer_t {
   struct bpf_spin_lock lock;
   int pid;
   int uid;
   int num_bytes;
   char message[DATA_BUFFER_SIZE];
   bool can_write;
};


