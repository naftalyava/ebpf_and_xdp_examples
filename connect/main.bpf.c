#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf_endian.h>
#include "main.h"
//#include <linux/ip.h>

#ifndef AF_INET
#define AF_INET 2 // Internet IP Protocol
#endif

#ifndef AF_INET6
#define AF_INET6 10 // IP version 6
#endif

// struct sockaddr_in {
//     __u16 sin_family; // Address family
//     __u16 sin_port;   // Port number
//     __u32 sin_addr;   // IPv4 address
// };

// struct sockaddr_in6 {
//     __u16 sin6_family;   // Address family
//     __u16 sin6_port;     // Port number
//     __u32 sin6_flowinfo; // IPv6 flow information
//     __u8 sin6_addr[16];  // IPv6 address
//     __u32 sin6_scope_id; // Scope ID
// };



// #define htons(x) ((__be16)___constant_swab16((x)))
// #define htonl(x) ((__be32)___constant_swab32((x)))


#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[300]);
    __type(value, char[300]);
} proc_hash SEC(".maps");


// int test(char *a, char *b)
// {
//     return a + b;
// }

//#define 	__bpf_htonl(x)   __builtin_bswap32(x)

SEC("kprobe/__x64_sys_connect")
int BPF_KPROBE(probe_connect, int sockfd, struct sockaddr *addr, int addrlen) {
    __u16 family = AF_INET;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    
    if (true || family == AF_INET) { // Check for IPv4
        struct sockaddr_in addr4;
        // Safely read the entire sockaddr_in structure
        if (bpf_probe_read_user(&addr4, sizeof(addr4), addr) == 0) {
            // Now that we've safely read the data into addr4, we can check the IP
            if (addr4.sin_addr.s_addr == bpf_htonl(0x08080808)) {
                // If the destination IP address is 8.8.8.8, override the syscall return value
                bpf_override_return(ctx, -1);
            }
            //bpf_override_return(ctx, -1);

        } else {
            //bpf_override_return(ctx, -1);
        }
    } 
    // Additional handling for AF_INET6 could be added here if necessary
    //bpf_override_return(ctx, -1);
    return 0;
}




char LICENSE[] SEC("license") = "Dual BSD/GPL";
