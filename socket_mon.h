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
   bool can_read;
   bool can_write;
};


struct read_exit_data_t {
   struct bpf_spin_lock lock;
   int pid;
   int uid;
   int num_bytes_desired;
   int num_bytes_got;
   char read_data[256];
   bool can_read;
   bool can_write;
};


