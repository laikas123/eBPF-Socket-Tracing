#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "socket_mon.h"
#include "socket_mon.skel.h"
#include <dirent.h> 
#include <fcntl.h>
#include <time.h>
#include <stdint.h> 
#include <sys/socket.h>


#define SEC_TO_NS(sec) ((sec)*1000000000)

const char* domain_to_str(int domain);
const char* type_to_str(int type);
const char* protocol_to_str(int protocol);


void timestamp()
{
    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    printf("%s",asctime( localtime(&ltime) ) );
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

int handle_event_read(void *ctx, void *data, size_t data_sz)
{
	//convert data from buffer to struct
	struct socket_data_t *kern_data = data;

	const char* domain_str = domain_to_str(kern_data -> domain);
	const char* type_str = type_to_str(kern_data -> type);
	const char* protocol_str = protocol_to_str(kern_data -> protocol);


	if(kern_data -> domain == AF_BLUETOOTH){
		printf("pid = %d  uid = %d domain = %s type = %s protocol = %s\n", kern_data -> pid, kern_data -> uid, domain_str, type_str, protocol_str);
	}




	return 0;
	
}


const char* domain_to_str(int domain) {
	switch(domain) {
		case AF_UNSPEC: return "AF_UNSPEC";
		case AF_UNIX:	 return "AF_UNIX:";
		case AF_INET: return "AF_INET";
		case AF_AX25: return "AF_AX25";
		case AF_IPX: return "AF_IPX";
		case AF_APPLETALK: return "AF_APPLETALK";
		case AF_NETROM: return "AF_NETROM";
		case AF_BRIDGE: return "AF_BRIDGE";
		case AF_ATMPVC: return "AF_ATMPVC";
		case AF_X25: return "AF_X25";
		case AF_INET6: return "AF_INET6";
		case AF_ROSE:		 return "AF_ROSE:";
		case AF_DECnet: return "AF_DECnet";
		case AF_NETBEUI: return "AF_NETBEUI";
		case AF_SECURITY: return "AF_SECURITY";
		case AF_KEY: return "AF_KEY";
		case AF_NETLINK: return "AF_NETLINK";
		case AF_PACKET: return "AF_PACKET";
		case AF_ASH: return "AF_ASH";
		case AF_ECONET: return "AF_ECONET";
		case AF_ATMSVC: return "AF_ATMSVC";
		case AF_RDS: return "AF_RDS";
		case AF_SNA: return "AF_SNA";
		case AF_IRDA: return "AF_IRDA";
		case AF_PPPOX: return "AF_PPPOX";
		case AF_WANPIPE: return "AF_WANPIPE";
		case AF_LLC: return "AF_LLC";
		case AF_IB: return "AF_IB";
		case AF_MPLS: return "AF_MPLS";
		case AF_CAN: return "AF_CAN";
		case AF_TIPC: return "AF_TIPC";
		case AF_BLUETOOTH: return "AF_BLUETOOTH";
		case AF_IUCV: return "AF_IUCV";
		case AF_RXRPC: return "AF_RXRPC";
		case AF_ISDN: return "AF_ISDN";
		case AF_PHONET: return "AF_PHONET";
		case AF_IEEE802154: return "AF_IEEE802154";
		case AF_CAIF: return "AF_CAIF";
		case AF_ALG: return "AF_ALG";
		case AF_NFC: return "AF_NFC";
		case AF_VSOCK: return "AF_VSOCK";
		case AF_KCM: return "AF_KCM";
		case AF_QIPCRTR: return "AF_QIPCRTR";
		case AF_SMC: return "AF_SMC";
		case AF_XDP: return "AF_XDP";
		case AF_MCTP: return "AF_MCTP";
		case AF_MAX: return "AF_MAX";
		default: return "AF_UNSPEC";

	}
}


const char* type_to_str(int type) {


	//"Since Linux 2.6.27, the type argument serves a second purpose: in addition to 
	//specifying a socket type, it may include the bitwise OR of any of the following 
	//values, to modify the behavior of socket(): "
	//
	//
	//need to only get lowest 4 bits
	//there's less than 10 types so they 
	//fit in lowest 4 bits, this is due
	//to the above excerpt from the socket
	//man page
	switch(type & 0x0000000F) {
		case SOCK_STREAM: return "SOCK_STREAM";
		case SOCK_DGRAM:  return "SOCK_DGRAM";	
		case SOCK_RAW:  return "SOCK_RAW";
		case SOCK_RDM:  return "SOCK_RDM";	
		case SOCK_SEQPACKET:  return "SOCK_SEQPACKET";		
		case SOCK_PACKET:  return "SOCK_PACKET";
		default: return "UNKOWN!";
		         
	}

}


const char* protocol_to_str(int protocol) {

	switch(protocol) {
		case 0:	return "IP";			
		case 1:	return "ICMP";		
		case 2:	return "IGMP";		
		case 3:	return "GGP";		
		case 4:	return "IP-ENCAP";	
		case 5:	return "ST";		
		case 6:	return "TCP";		
		case 8:	return "EGP";		
		case 9:	return "IGP";		
		case 12: return "PUP";		
		case 17: return "UDP";		
		case 20: return "HMP";		
		case 22: return "XNS-IDP";		
		case 27: return "RDP";	
		case 29: return "ISO-TP4";		
		case 33: return "DCCP";		
		case 36: return "XTP";		
		case 37: return "DDP";		
		case 38: return "IDPR-CMTP";	
		case 41: return "IPv6";		
		case 43: return "IPv6-Route";	
		case 44: return "IPv6-Frag";	
		case 45: return "IDRP";		
		case 46: return "RSVP";		
		case 47: return "GRE";		
		case 50: return "IPSEC-ESP";	
		case 51: return "IPSEC-AH";	
		case 57: return "SKIP";		
		case 58: return "IPv6-ICMP";	
		case 59: return "IPv6-NoNxt";	
		case 60: return "IPv6-Opts";	
		case 73: return "RSPF CPHB";	
		case 81: return "VMTP";	
		case 88: return "EIGRP";		
		case 89: return "OSPFIGP";		
		case 93: return "AX.25";		
		case 94: return "IPIP";		
		case 97: return "ETHERIP";		
		case 98: return "ENCAP";		
		case 99: return "PRIVATE_ENCRYP!";	
		case 103: return "PIM";	
		case 108: return "IPCOMP";		
		case 112: return "VRRP";		
		case 115: return "L2TP";		
		case 124: return "ISIS";		
		case 132: return "SCTP";		
		case 133: return "FC";	
		case 135:   return "Mobility-Header"; 
		case 136: return "UDPLite";		
		case 137: return "MPLS-in-IP";	
		case 138: return "MANET!";
		case 139: return "HIP";		
		case 140: return "Shim6";		
		case 141: return "WESP";		
		case 142: return "ROHC";
		default: return "UNKNOWN!";
	}

}


int main()
{
    struct socket_mon_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct ring_buffer *rb_read = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = socket_mon_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = socket_mon_bpf__load(skel);
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	
	if (err) {
		printf("Failed to load BPF object\n");
		socket_mon_bpf__destroy(skel);
		return 1;
	}

	// Attach the progams to the events
	err = socket_mon_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		socket_mon_bpf__destroy(skel);
        return 1;
	}

	//initialize ring buffer connection
	rb_read = ring_buffer__new(bpf_map__fd(skel->maps.output_socket), handle_event_read, NULL, NULL);
	if (!rb_read) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		socket_mon_bpf__destroy(skel);
        return 1;
	}

	//poll the ring buffer repeatedly
	while (true) {
		err = ring_buffer__poll(rb_read, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		
	}

	ring_buffer__free(rb_read);
	socket_mon_bpf__destroy(skel);
	return -err;
}
