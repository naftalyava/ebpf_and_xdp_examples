#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

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

SEC("kprobe/__x64_sys_execve")
int probe_execve(struct pt_regs *ctx)
{
    // struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    // char *filename = (char *)(PT_REGS_PARM1(ctx2));

    struct data_t data = { '\0' };

    // #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    // char *filename = (char *)PT_REGS_PARM1(ctx);
    // unsigned long argv = PT_REGS_PARM2(ctx);
    // data.debug1 = 1;
    // #else
    // LAMA KAHA?!?!?!
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char *filename = (char *)READ_KERN(PT_REGS_PARM1(ctx2));
    //unsigned long argv = READ_KERN(PT_REGS_PARM2(ctx2));
    data.debug1 = 2;
    //#endif



    
    data.op_code = 3; // Use an appropriate operation code for execve tracing

    // The first parameter of sys_execve is the filename as a user-space pointer
    int res = bpf_probe_read_user(&data.oldpath, sizeof(data.oldpath), filename);


    // Use bpf_probe_read_user_str() to safely read strings from user space
    //int res = bpf_probe_read_str(&data.oldpath, sizeof(data.oldpath), filename);
    data.debug = res;


    

    //if (filename[0] == '/' && filename[1] == 't') {
            data.debug1 = 22;
            //bpf_override_return(ctx, -1);
    //}

    // if (bpf_map_lookup_elem(&proc_hash, data.oldpath)) {
    // //         bpf_override_return(ctx, -1);;
    //             data.debug1 = 22;
    //  } 

    if (bpf_map_lookup_elem(&proc_hash, &data.oldpath)) {
        // If the filename is found in the map, set debug1 to indicate special handling
        data.debug1 = 100;
        // Here you could decide to take further actions, like logging or blocking the syscall
        // Uncomment the following line if you intend to block the syscall
        bpf_override_return(ctx, -1);
    } else {
        data.debug1 = 200;
        //data.debug1 = test(100,100);
    }

    char str[50] = "/usr/bin/date";
    bool found = false;
    bool stop = false;
    for (int i = 0 ; i < 300 && !stop ; i++) {
        if (str[i] == '\0' && data.oldpath[i] == '\0'){ 
            found = true;
            break;
        }

        if (str[i] == data.oldpath[i]) {
            continue;
        } else {
            found = false;
            stop = true;
            //break;
        }
    }

    if (found) bpf_override_return(ctx, -1);


    // Output the captured data to the ring buffer
    bpf_ringbuf_output(&ringbuf, &data, sizeof(data), BPF_RB_FORCE_WAKEUP);



    return 0;
}




char LICENSE[] SEC("license") = "Dual BSD/GPL";
