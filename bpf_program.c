#include <uapi/linux/ptrace.h>

#define MAX_STACK_DEPTH 5
#define MAX_FUNC_NAME_LEN 64

typedef struct {
    char func_names[MAX_STACK_DEPTH][MAX_FUNC_NAME_LEN];
    u64 depth;
} FunctionStack;

typedef struct {
    u64 ts;
    u64 pid;
    u64 tid;
    u64 depth;
    u64 is_return;
    char file_name[MAX_FUNC_NAME_LEN];
    char func_name[MAX_FUNC_NAME_LEN];
    int lineno;
} FunctionTraceEvent;

typedef struct {
    u64 ts;
    u64 pid;
    u64 tid;
    u64 duration;
    u64 depth;
    int entry_lineno;
    int return_lineno;
    char file_name[MAX_FUNC_NAME_LEN];
    char func_name[MAX_FUNC_NAME_LEN];
    char func_names[MAX_STACK_DEPTH][MAX_FUNC_NAME_LEN];
} CompletedStackEvent;

BPF_PERF_OUTPUT(trace_events);
BPF_PERF_OUTPUT(completed_stacks);
BPF_HASH(function_stacks, u64, FunctionStack);

// Store entry line numbers and start timestamps for each stack depth
BPF_HASH(depth_entry_linenos, u64, int);
BPF_HASH(depth_start_ts, u64, u64);

// Define per-CPU arrays for large structs
BPF_PERCPU_ARRAY(entry_data, FunctionTraceEvent, 1);
BPF_PERCPU_ARRAY(return_data, CompletedStackEvent, 1);

static __always_inline FunctionStack* get_or_create_stack(u64 key) {
    FunctionStack *stack = function_stacks.lookup(&key);
    if (stack == NULL) {
        FunctionStack new_stack = {};
        new_stack.depth = 0;
        function_stacks.update(&key, &new_stack);
        stack = function_stacks.lookup(&key);
    }
    return stack;
}

int trace_entry(struct pt_regs *ctx) {
    // Use per-CPU map instead of on-stack variable
    int zero = 0;
    FunctionTraceEvent *data = entry_data.lookup(&zero);
    if (!data) {
        return 0;
    }

    data->ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    data->tid = pid_tgid;

    // Read arguments from USDT probes
    bpf_usdt_readarg_p(1, ctx, &data->file_name, sizeof(data->file_name));
    bpf_usdt_readarg_p(2, ctx, &data->func_name, sizeof(data->func_name));
    bpf_usdt_readarg(3, ctx, &data->lineno);

    u64 key = ((u64)data->pid << 32) | (u64)data->tid;
    FunctionStack *stack = get_or_create_stack(key);
    if (!stack) {
        return 0;
    }

    // Create a composite key for the depth maps
    u64 depth_key = (key << 32) | stack->depth;
    
    // Store the entry line number and start timestamp for the current depth
    depth_entry_linenos.update(&depth_key, &data->lineno);
    depth_start_ts.update(&depth_key, &data->ts);

    u64 depth = stack->depth;
    if (depth < MAX_STACK_DEPTH) {
        // Safely copy the function name
        __builtin_memcpy(stack->func_names[depth], data->func_name, MAX_FUNC_NAME_LEN);
        // Increment depth
        stack->depth = depth + 1;
    }

    return 0;
}

int trace_return(struct pt_regs *ctx) {
    // Use per-CPU map instead of on-stack variable
    int zero = 0;
    CompletedStackEvent *completed_stack = return_data.lookup(&zero);
    if (!completed_stack) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    completed_stack->pid = pid_tgid >> 32;
    completed_stack->tid = pid_tgid;

    // Read arguments from USDT probes
    bpf_usdt_readarg_p(1, ctx, &completed_stack->file_name, sizeof(completed_stack->file_name));
    bpf_usdt_readarg_p(2, ctx, &completed_stack->func_name, sizeof(completed_stack->func_name));
    bpf_usdt_readarg(3, ctx, &completed_stack->return_lineno);

    u64 key = ((u64)completed_stack->pid << 32) | (u64)completed_stack->tid;
    FunctionStack *stack = function_stacks.lookup(&key);
    if (!stack) {
        return 0;
    }

    u64 depth = stack->depth;
    if (depth == 0) {
        return 0;  // This shouldn't happen, but let's guard against it
    }
    // Create a composite key for the depth maps
    u64 depth_key = (key << 32) | (depth - 1);
    // Lookup the entry line number and start timestamp for the current depth
    int* entry_lineno_ptr = depth_entry_linenos.lookup(&depth_key);
    u64* start_ts_ptr = depth_start_ts.lookup(&depth_key);
    if (!entry_lineno_ptr || !start_ts_ptr) {
        return 0;
    }

    completed_stack->duration = bpf_ktime_get_ns() - *start_ts_ptr;
    completed_stack->ts = *start_ts_ptr;
    completed_stack->entry_lineno = *entry_lineno_ptr;

    if (depth <= MAX_STACK_DEPTH) {
        stack->depth = depth - 1;
        completed_stack->depth = depth;

        #pragma unroll
        for (int i = 0; i < MAX_STACK_DEPTH; i++) {
            if (i < depth) {
                __builtin_memcpy(
                    &completed_stack->func_names[i],
                    stack->func_names[i],
                    MAX_FUNC_NAME_LEN
                );
            } else {
                break;
            }
        }
        completed_stacks.perf_submit(ctx, completed_stack, sizeof(*completed_stack));

        if (depth == 1) {
            function_stacks.delete(&key);
            // Clean up the depth map entries for this thread
            #pragma unroll
            for (int i = 0; i < MAX_STACK_DEPTH; i++) {
                u64 cleanup_key = (key << 32) | i;
                depth_entry_linenos.delete(&cleanup_key);
                depth_start_ts.delete(&cleanup_key);
            }
        }
    }

    return 0;
}
