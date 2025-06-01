/*
 *  Tecnion CS 236652 Computer Security - Skeleton Security Module
 *
 *  This file contains the Computer Security hook function implementations.
 *
 *  Author:  Sara Bitan, <sarab@cs.technion.ac.il>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>    /* for local_port_range[] */
#include <net/tcp.h>    /* struct or_callable used in sock_rcv_skb */
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>  /* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>    /* for Unix socket types */
#include <net/af_unix.h>  /* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>


#ifdef CONFIG_SECURITY_COMPSEC 

#define COMPSEC_CLASS_UNCLASSIFIED 0U
#define COMPSEC_CLASS_TOP_SECRET 3U
#define COMPSEC_EA_NAME "security.compsec"
#define COMPSEC_INIT_PID 1
extern struct security_operations *security_ops;

struct file_accesses {
  unsigned int class;
};

static void print_bad_access(const char *process_name, unsigned int process_class,
           const char *file_name, unsigned int file_class)
{
  pr_info("compsec: %s, %u, %s, %u\n", process_name, process_class, file_name, file_class); 
}

static int compsec_set_mnt_opts(struct super_block *sb,
                                struct security_mnt_opts *opts)
{
  return 0;
}

static void compsec_sb_clone_mnt_opts(const struct super_block *oldsb,
                                      struct super_block *newsb)
{
}

static int compsec_parse_opts_str(char *options,
                                  struct security_mnt_opts *opts)
{
  return 0;
}

static int compsec_sb_show_options(struct seq_file *m, struct super_block *sb)
{
  return 0;
}
/* Hook functions begin here. */

static int compsec_ptrace_access_check(struct task_struct *child,
                                       unsigned int mode)
{
  return 0;
}

static int compsec_ptrace_traceme(struct task_struct *parent)
{
  return 0;
}

static int compsec_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
  return 0;
}

static int compsec_capset(struct cred *new, const struct cred *old,
                          const kernel_cap_t *effective,
                          const kernel_cap_t *inheritable,
                          const kernel_cap_t *permitted)
{
  return 0;
}

/*
 * (This comment used to live with the compsec_task_setuid hook,
 * which was removed).
 *
 * Since setuid only affects the current process, and since the SELinux
 * controls are not based on the Linux identity attributes, SELinux does not
 * need to control this operation.  However, SELinux does control the use of
 * the CAP_SETUID and CAP_SETGID capabilities using the capable hook.
 */

static int compsec_capable(struct task_struct *tsk, const struct cred *cred,
                           struct user_namespace *ns, int cap, int audit)
{
  return 0;
}

static int compsec_quotactl(int cmds, int type, int id, struct super_block *sb)
{
  return 0;
}

static int compsec_quota_on(struct dentry *dentry)
{
  return 0;
}

static int compsec_syslog(int type)
{
  return 0;
}

/*
 * Check that a process has enough memory to allocate a new virtual
 * mapping. 0 means there is enough memory for the allocation to
 * succeed and -ENOMEM implies there is not.
 *
 * Do not audit the selinux permission check, as this is applied to all
 * processes that allocate mappings.
 */
static int compsec_vm_enough_memory(struct mm_struct *mm, long pages)
{
  return 0;
}

/* binprm security operations */

static int compsec_bprm_set_creds(struct linux_binprm *bprm)
{
	unsigned int file_class;
  int len;
  unsigned int* new_exec_security;
  // int rc;
  
  if (!bprm || !bprm->file || !bprm->file->f_path.dentry || !bprm->cred) {
     return 0;
  }

  // // TODO: REMOVE BEFORE SUBMITTING
  // pr_info("Entered %s with pid %d\n", __func__);

  /*
	 * Do only if this function is called for the first time of an execve operation.
	 */
  // if (bprm->cred_prepared)
  //   return 0;

  // rc = cap_bprm_set_creds(bprm);
  // if (rc)
	//   return rc;

  new_exec_security = (unsigned int *)bprm->cred->security;
  if (!new_exec_security)
    return -EACCES;

	len = vfs_getxattr(bprm->file->f_path.dentry, COMPSEC_EA_NAME, &file_class, sizeof(file_class));
	if (len < sizeof(file_class)) {
	  file_class = COMPSEC_CLASS_UNCLASSIFIED;
  }

  *new_exec_security = file_class;

	return 0;
}

static int compsec_bprm_check_security(struct linux_binprm *bprm)
{
  if (bprm->file->f_dentry->d_inode->i_ino == (unsigned long) 280615) {
    printk ("compsec: can't exec this file\n");
    return (-EACCES);
  }
  return 0;
}


static int compsec_bprm_secureexec(struct linux_binprm *bprm)
{
  return 0;
}

/*
 * Prepare a process for imminent new credential changes due to exec
 */
static void compsec_bprm_committing_creds(struct linux_binprm *bprm)
{
}

/*
 * Clean up the process immediately after the installation of new credentials
 * due to exec
 */
static void compsec_bprm_committed_creds(struct linux_binprm *bprm)
{
}

/* superblock security operations */

static int compsec_sb_alloc_security(struct super_block *sb)
{
  return 0;
}

static void compsec_sb_free_security(struct super_block *sb)
{
}

static inline int compsec_option(char *option, int len)
{
  return 0;
}

static int compsec_sb_copy_data(char *orig, char *copy)
{
  return 0;
}

static int compsec_sb_remount(struct super_block *sb, void *data)
{
  return 0;
}

static int compsec_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
  return 0;
}

static int compsec_sb_statfs(struct dentry *dentry)
{
  return 0;
}

static int compsec_mount(char *dev_name,
                         struct path *path,
                         char *type,
                         unsigned long flags,
                         void *data)
{
  return 0;
}

static int compsec_umount(struct vfsmount *mnt, int flags)
{
  return 0;
}

/* inode security operations */

static int compsec_inode_alloc_security(struct inode *inode)
{
  inode->i_security = kzalloc(sizeof(struct file_accesses),GFP_KERNEL);
  if ( !inode->i_security ) {
    printk(KERN_DEBUG "compsec: kzalloc failed \n");
  }
  return !inode->i_security;
}

static void compsec_inode_free_security(struct inode *inode)
{
  if (inode->i_security) {
    kfree(inode->i_security);
    inode->i_security = NULL;
  }
} 

static int compsec_inode_init_security(struct inode *inode, struct inode *dir,
                                       const struct qstr *qstr, char **name,
                                       void **value, size_t *len)
{
  return 0;
}

static int compsec_inode_create(struct inode *dir, struct dentry *dentry, int mask)
{
  return 0;
}

static int compsec_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
  return 0;  
}

static int compsec_inode_unlink(struct inode *dir, struct dentry *dentry)
{
  return 0;
}

static int compsec_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
  return 0;
}

static int compsec_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
  return 0;
}

static int compsec_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
  return 0;
}

static int compsec_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
  return 0;
}

static int compsec_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
        struct inode *new_inode, struct dentry *new_dentry)
{
  return 0;
}

static int compsec_inode_readlink(struct dentry *dentry)
{
  return 0;
}

static int compsec_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
  return 0;
}

static int compsec_inode_permission(struct inode *inode, int mask)
{
  return 0;
}

static int compsec_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
  return 0;
}

static int compsec_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
  return 0;
}

static int compsec_inode_setxattr(struct dentry *dentry, const char *name,
                                  const void *value, size_t size, int flags)
{
  unsigned int *process_security;
  unsigned int process_class;
  ssize_t len;
  void *file_class_memory;
  unsigned int file_class;

  file_class_memory = kzalloc(size, GFP_KERNEL);
  if (!file_class_memory)
    return -ENOMEM;

  len = vfs_getxattr(dentry, name, file_class_memory, size);
  if (len < size) {
    file_class = COMPSEC_CLASS_UNCLASSIFIED;
  } else {
    file_class = *(unsigned int *)file_class_memory;
  }

  kfree(file_class_memory);

  process_security = (unsigned int *)current_cred()->security;
  if (!process_security)
    return -ENOMEM;

  process_class = *process_security;

  if (process_class > file_class)
    return -EACCES;

  vfs_setxattr(dentry, name, value, size, flags);

  return 0;
}

static void compsec_inode_post_setxattr(struct dentry *dentry, const char *name,
                                        const void *value, size_t size,
                                        int flags)
{
}

static int compsec_inode_getxattr(struct dentry *dentry, const char *name)
{
  // struct file_accesses *process_security;
  // unsigned int file_class;
  // unsigned int process_class;
  // ssize_t len;

  // len = vfs_getxattr(dentry, name, (void*)&file_class, sizeof(unsigned int));
  // if (len < 0)
  //   return -EACCES;

  // process_security = (struct file_accesses *)current_cred()->security;
  // if (!process_security)
  //   return -EACCES;

  // process_class = process_security->class;

  // if (process_class > file_class)
  //   return -EACCES;
  
  return 0;
}

static int compsec_inode_listxattr(struct dentry *dentry)
{
  return 0;
}

static int compsec_inode_removexattr(struct dentry *dentry, const char *name)
{
  struct inode *inode;
  unsigned int *process_security;
  unsigned int file_class;
  unsigned int process_class;
  void *value;
  ssize_t size;
  const char *suffix;

  if (current->pid == COMPSEC_INIT_PID)
    return 0; // allow init to do anything

  if (strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN)) {
		suffix = name + XATTR_SECURITY_PREFIX_LEN;  
  } else {
    suffix = name;
  }

  inode = dentry->d_inode;
  value = NULL;
  size = xattr_getsecurity(inode, suffix, NULL, 0);
  if (size < 0)
    return -EACCES;

  value = kzalloc(sizeof(unsigned int), GFP_KERNEL);
  if (!value)
    return -ENOMEM;

  size = xattr_getsecurity(inode, suffix, value, size);
  if (size < sizeof(unsigned int))
    return -EACCES;

  file_class = *(unsigned int *)value;
  kfree(value);
  
  process_security = (unsigned int*)current_cred()->security;
  if (!process_security) {
    return -EACCES;
  }

  process_class = *process_security;

  if (process_class > file_class)
    return -EACCES;

  return 0;
}

/*
 * Copy the inode security context value to the user.
 *
 * Permission check is handled by compsec_inode_getxattr hook.
 */
static int compsec_inode_getsecurity(const struct inode *inode, const char *name, void **buffer,
                                     bool alloc)
{
  struct dentry *dentry_from_inode;
  void *file_class;
	ssize_t len;
  
  if (!alloc) {
		return 0;
	}

  file_class = kzalloc(sizeof(unsigned int), GFP_KERNEL);
  if (!file_class)
    return -ENOMEM;

	dentry_from_inode = d_find_alias((struct inode *)inode);  
  if (!dentry_from_inode) {
    kfree (file_class);
    return -EINVAL;
  }

	len = vfs_getxattr(dentry_from_inode, name, file_class, sizeof(unsigned int));
	if (len < 0) {
    kfree (file_class);
    dput(dentry_from_inode);
    return len;
  }

  *buffer = file_class;
  dput(dentry_from_inode);

  return len;
}

static int compsec_inode_setsecurity(struct inode *inode, const char *name,
                                     const void *value, size_t size, int flags)
{
  // struct file_accesses *process_security;
  // unsigned int process_class;
  // struct dentry *dentry_from_inode;
  // int ret;
  // ssize_t len;

  // unsigned int current_file_class;

  // dentry_from_inode = d_find_alias(inode);
  // len = vfs_getxattr(dentry_from_inode, COMPSEC_EA_NAME, (void*)&current_file_class,
  //                    sizeof(unsigned int));
  // if (len < 0) {
  //   current_file_class = COMPSEC_CLASS_UNCLASSIFIED;
  // }

  // process_security = (struct file_accesses*) current_cred()->security;
  // if (!process_security) {
  //   process_class = COMPSEC_CLASS_UNCLASSIFIED;
  // } else {
  //   process_class = process_security->class;
  // }
  
  // if (process_class <= current_file_class || current->pid == COMPSEC_INIT_PID)  {
  //   ret = vfs_setxattr(dentry_from_inode, name, value, size, flags);
  //   if (ret)
  //     return ret;
  //   return 0;
  // }

  // return -EACCES;
  return 0;
}

static int compsec_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
  return 0;
}

static void compsec_inode_getsecid(const struct inode *inode, u32 *secid)
{
}

/* file security operations */

static int compsec_file_permission(struct file *file, int mask)
{
  unsigned int file_class;
  struct dentry *file_dentry;
  const char* filename;
  struct inode *inode;
  int len;
  unsigned int process_class;
  char process_name[sizeof(current->comm)];
  unsigned int *process_security;

  if (current->pid == COMPSEC_INIT_PID || current->tgid == COMPSEC_INIT_PID)
      return 0; // allow init to do anything

  if (!file)
      return -EINVAL;  

  file_dentry = file->f_path.dentry;
  if (!file_dentry)
    return -EINVAL;

  inode = file_dentry->d_inode;
  if (!inode)
      return -EINVAL;

  if (inode->i_rdev || !S_ISREG(inode->i_mode))
    return 0; // we are not enforcing on char/block devices or non regular files

  filename = file_dentry->d_name.name;

  process_security = (unsigned int *)current_cred()->security;
  if (!process_security)
    return -EACCES;

  get_task_comm(process_name, current);
  process_class = *process_security;

  len = vfs_getxattr(file_dentry, COMPSEC_EA_NAME, &file_class, sizeof(file_class));

  if (len != sizeof(file_class))
    file_class = COMPSEC_CLASS_UNCLASSIFIED;
  
  if (file_class > COMPSEC_CLASS_TOP_SECRET)
    file_class = COMPSEC_CLASS_UNCLASSIFIED;

	if (len < sizeof(unsigned int))
    file_class = COMPSEC_CLASS_UNCLASSIFIED;

  /*
  * Reminder:
  * #define MAY_EXEC		  0x00000001
  * #define MAY_WRITE		  0x00000002
  * #define MAY_READ		  0x00000004
  * #define MAY_APPEND		0x00000008
  * #define MAY_ACCESS		0x00000010
  * #define MAY_OPEN		  0x00000020
  * #define MAY_CHDIR		  0x00000040
  */
   if ((mask & MAY_WRITE) || (mask & MAY_APPEND)) {
    if (process_class <= file_class) {
      return 0;
    } else {
      print_bad_access(process_name, process_class, filename, file_class);
      return -EACCES;
    }
  }

  if (mask & MAY_READ) {
    if (process_class >= file_class) {
      return 0;
    } else {
      print_bad_access(process_name, process_class, filename, file_class);
      return -EACCES;
    }
  }

  return 0;
}

static int compsec_file_alloc_security(struct file *file)
{
  return 0;
}

static void compsec_file_free_security(struct file *file)
{
}

static int compsec_file_ioctl(struct file *file, unsigned int cmd,
            unsigned long arg)
{
  return 0;
}


static int compsec_file_mmap(struct file *file, unsigned long reqprot,
           unsigned long prot, unsigned long flags,
           unsigned long addr, unsigned long addr_only)
{
  return 0;
}

static int compsec_file_mprotect(struct vm_area_struct *vma,
         unsigned long reqprot,
         unsigned long prot)
{
  return 0;
}

static int compsec_file_lock(struct file *file, unsigned int cmd)
{
  return 0;
}

static int compsec_file_fcntl(struct file *file, unsigned int cmd,
            unsigned long arg)
{
  return 0;
}

static int compsec_file_set_fowner(struct file *file)
{
  return 0;
}

static int compsec_file_send_sigiotask(struct task_struct *tsk,
               struct fown_struct *fown, int signum)
{
  return 0;
}

static int compsec_file_receive(struct file *file)
{
  return 0;
}

static int compsec_dentry_open(struct file *file, const struct cred *cred)
{
  return 0;
}

/* task security operations */

static int compsec_task_create(unsigned long clone_flags)
{
  return 0;
}

/*
 * allocate the SELinux part of blank credentials
 */
static int compsec_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
  unsigned int *cred_security;
  
  cred_security = kmalloc(sizeof(unsigned int), gfp);

  if (!cred_security)
    return -ENOMEM;
  
  *cred_security = COMPSEC_CLASS_UNCLASSIFIED;

  cred->security = cred_security;

  return 0;
}

/*
 * detach and free the LSM part of a set of credentials
 */
static void compsec_cred_free(struct cred *cred)
{
  unsigned int *cred_security;
  cred_security = cred->security;
  if (cred_security)
    kfree(cred_security);
  cred->security = NULL;
}

/*
 * prepare a new set of credentials for modification
 */
static int compsec_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
  const unsigned int *old_cred_class;
  unsigned int *new_cred_class;

  old_cred_class = old->security;

  new_cred_class = kmalloc(sizeof(unsigned int), gfp);
  if (!new_cred_class)
    return -ENOMEM;

  if (!old_cred_class) {
    *new_cred_class = COMPSEC_CLASS_UNCLASSIFIED;
  } else {
   *new_cred_class = *old_cred_class; 
  }
  new->security = (void*)new_cred_class;

  return 0;
}

/*
 * transfer the SELinux data to a blank set of creds
 */
static void compsec_cred_transfer(struct cred *new, const struct cred *old)
{
}

/*
 * set the security data for a kernel service
 * - all the creation contexts are set to unlabelled
 */
static int compsec_kernel_act_as(struct cred *new, unsigned int secid)
{
  return 0;
}

/*
 * set the file creation context in a security record to the same as the
 * objective context of the specified inode
 */
static int compsec_kernel_create_files_as(struct cred *new, struct inode *inode)
{
  return 0;
}

static int compsec_kernel_module_request(char *kmod_name)
{
  return 0;
}

static int compsec_task_setpgid(struct task_struct *p, pid_t pgid)
{
  return 0;
}

static int compsec_task_getpgid(struct task_struct *p)
{
  return 0;
}

static int compsec_task_getsid(struct task_struct *p)
{
  return 0;
}

static void compsec_task_getsecid(struct task_struct *p, unsigned int *secid)
{
}

static int compsec_task_setnice(struct task_struct *p, int nice)
{
  return 0;
}

static int compsec_task_setioprio(struct task_struct *p, int ioprio)
{
  return 0;
}

static int compsec_task_getioprio(struct task_struct *p)
{
  return 0;
}

static int compsec_task_setrlimit(struct task_struct *p, unsigned int resource,
                                  struct rlimit *new_rlim)
{

  return 0;
}

static int compsec_task_setscheduler(struct task_struct *p)
{
  return 0;
}

static int compsec_task_getscheduler(struct task_struct *p)
{
  return 0;
}

static int compsec_task_movememory(struct task_struct *p)
{
  return 0;
}

static int compsec_task_kill(struct task_struct *p, struct siginfo *info,
                             int sig, unsigned int secid)
{
  return 0;
}

static int compsec_task_wait(struct task_struct *p)
{
  return 0;
}

static void compsec_task_to_inode(struct task_struct *p,
                                  struct inode *inode)
{
}





/**
 * compsec_skb_peerlbl_sid - Determine the peer label of a packet
 * @skb: the packet
 * @family: protocol family
 * @sid: the packet's peer label SID
 *
 * Description:
 * Check the various different forms of network peer labeling and determine
 * the peer label/SID for the packet; most of the magic actually occurs in
 * the security server function security_net_peersid_cmp().  The function
 * returns zero if the value in @sid is valid (although it may be SECSID_NULL)
 * or -EACCES if @sid is invalid due to inconsistencies with the different
 * peer labels.
 *
 */


/**
 * compsec_conn_sid - Determine the child socket label for a connection
 * @sk_sid: the parent socket's SID
 * @skb_sid: the packet's SID
 * @conn_sid: the resulting connection SID
 *
 * If @skb_sid is valid then the user:role:type information from @sk_sid is
 * combined with the MLS information from @skb_sid in order to create
 * @conn_sid.  If @skb_sid is not valid then then @conn_sid is simply a copy
 * of @sk_sid.  Returns zero on success, negative values on failure.
 *
 */


/* socket security operations */


static int compsec_socket_create(int family, int type,
                                 int protocol, int kern)
{
  return 0;
}

static int compsec_socket_post_create(struct socket *sock, int family,
                                      int type, int protocol, int kern)
{
  return 0;
}

/* Range of port numbers used to automatically bind.
   Need to determine whether we should perform a name_bind
   permission check between the socket and the port number. */

static int compsec_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
  return 0;
}

static int compsec_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
  return 0;
}

static int compsec_socket_listen(struct socket *sock, int backlog)
{
  return 0;
}

static int compsec_socket_accept(struct socket *sock, struct socket *newsock)
{
  return 0;
}

static int compsec_socket_sendmsg(struct socket *sock, struct msghdr *msg,
                                  int size)
{
  return 0;
}

static int compsec_socket_recvmsg(struct socket *sock, struct msghdr *msg,
                                  int size, int flags)
{
  return 0;
}

static int compsec_socket_getsockname(struct socket *sock)
{
  return 0;
}

static int compsec_socket_getpeername(struct socket *sock)
{
  return 0;
}

static int compsec_socket_setsockopt(struct socket *sock, int level, int optname)
{
  return 0;
}

static int compsec_socket_getsockopt(struct socket *sock, int level,
                                     int optname)
{
  return 0;
}

static int compsec_socket_shutdown(struct socket *sock, int how)
{
  return 0;
}

static int compsec_socket_unix_stream_connect(struct sock *sock, struct sock *other,
                                              struct sock *newsk)
{
  return 0;
}

static int compsec_socket_unix_may_send(struct socket *sock, struct socket *other)
{
  return 0;
}



static int compsec_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
  return 0;
}

static int compsec_socket_getpeersec_stream(struct socket *sock, char __user *optval,
                                            int __user *optlen, unsigned len)
{
  return 0;
}

static int compsec_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, unsigned int *secid)
{
  return 0;
}

static int compsec_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
  return 0;
}

static void compsec_sk_free_security(struct sock *sk)
{
}

static void compsec_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void compsec_sk_getsecid(struct sock *sk, unsigned int *secid)
{
}

static void compsec_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int compsec_inet_conn_request(struct sock *sk, struct sk_buff *skb,
                                     struct request_sock *req)
{
  return 0;
}

static void compsec_inet_csk_clone(struct sock *newsk,
                                   const struct request_sock *req)
{
}

static void compsec_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

static int compsec_secmark_relabel_packet(unsigned int sid)
{
  return 0;
}

static void compsec_secmark_refcount_inc(void)
{
}

static void compsec_secmark_refcount_dec(void)
{
}

static void compsec_req_classify_flow(const struct request_sock *req,
                                      struct flowi *fl)
{
}

static int compsec_tun_dev_create(void)
{
  return 0;
}

static void compsec_tun_dev_post_create(struct sock *sk)
{
}

static int compsec_tun_dev_attach(struct sock *sk)
{
  return 0;
}





static int compsec_netlink_send(struct sock *sk, struct sk_buff *skb)
{
  return 0;
}

static int compsec_netlink_recv(struct sk_buff *skb, int capability)
{
  return 0;
}


static int compsec_msg_msg_alloc_security(struct msg_msg *msg)
{
  return 0;
}

static void compsec_msg_msg_free_security(struct msg_msg *msg)
{
  
}

/* message queue security operations */
static int compsec_msg_queue_alloc_security(struct msg_queue *msq)
{
  return 0;
}

static void compsec_msg_queue_free_security(struct msg_queue *msq)
{

}

static int compsec_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
  return 0;
}

static int compsec_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
  return 0;
}

static int compsec_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
  return 0;
}

static int compsec_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
                                    struct task_struct *target,
                                    long type, int mode)
{
  return 0;
}

/* Shared Memory security operations */
static int compsec_shm_alloc_security(struct shmid_kernel *shp)
{
  return 0;
}

static void compsec_shm_free_security(struct shmid_kernel *shp)
{
}

static int compsec_shm_associate(struct shmid_kernel *shp, int shmflg)
{
  return 0;
}

/* Note, at this point, shp is locked down */
static int compsec_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
  return 0;
}

static int compsec_shm_shmat(struct shmid_kernel *shp,
                             char __user *shmaddr, int shmflg)
{
  return 0;
}

/* Semaphore security operations */
static int compsec_sem_alloc_security(struct sem_array *sma)
{
  return 0;
}

static void compsec_sem_free_security(struct sem_array *sma)
{
}

static int compsec_sem_associate(struct sem_array *sma, int semflg)
{
  return 0;
}

/* Note, at this point, sma is locked down */
static int compsec_sem_semctl(struct sem_array *sma, int cmd)
{
  return 0;
}

static int compsec_sem_semop(struct sem_array *sma, struct sembuf *sops,
                             unsigned nsops, int alter)
{
  return 0;
}

static int compsec_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
  return 0;
}

static void compsec_ipc_getsecid(struct kern_ipc_perm *ipcp, unsigned int *secid)
{
}

static void compsec_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int compsec_getprocattr(struct task_struct *p, char *name, char **value)
{
  return 0;
}

static int compsec_setprocattr(struct task_struct *p, char *name, void *value,
                               size_t size)
{
  return 0;
}

static int compsec_secid_to_secctx(unsigned int secid, char **secdata, unsigned int *seclen)
{
  return 0;
}

static int compsec_secctx_to_secid(const char *secdata, unsigned int seclen, unsigned int *secid)
{
  return 0;
}

static void compsec_release_secctx(char *secdata, unsigned int seclen)
{
  kfree(secdata);
}

/*
 *  called with inode->i_mutex locked
 */
static int compsec_inode_notifysecctx(struct inode *inode, void *ctx, unsigned int ctxlen)
{
  return 0;
}

/*
 *  called with inode->i_mutex locked
 */
static int compsec_inode_setsecctx(struct dentry *dentry, void *ctx, unsigned int ctxlen)
{
  return 0;
}

static int compsec_inode_getsecctx(struct inode *inode, void **ctx, unsigned int *ctxlen)
{
  return 0;
}
#ifdef CONFIG_KEYS

static int compsec_key_alloc(struct key *k, const struct cred *cred,
                             unsigned long flags)
{
  return 0;
}

static void compsec_key_free(struct key *k)
{
}

static int compsec_key_permission(key_ref_t key_ref, const struct cred *cred,
                                  key_perm_t perm)
{
  return 0;
}

static int compsec_key_getsecurity(struct key *key, char **_buffer)
{
  return 0;
}

#endif

static struct security_operations compsec_ops = {
  .name =                     "compsec",

  .ptrace_access_check =      compsec_ptrace_access_check,
  .ptrace_traceme =           compsec_ptrace_traceme,
  .capget =                   compsec_capget,
  .capset =                   compsec_capset,
  .capable =                  compsec_capable,
  .quotactl =                 compsec_quotactl,
  .quota_on =                 compsec_quota_on,
  .syslog =                   compsec_syslog,
  .vm_enough_memory =         compsec_vm_enough_memory,

  .netlink_send =             compsec_netlink_send,
  .netlink_recv =             compsec_netlink_recv,

  .bprm_set_creds =           compsec_bprm_set_creds,
  .bprm_check_security = 		  compsec_bprm_check_security,
  .bprm_committing_creds =    compsec_bprm_committing_creds,
  .bprm_committed_creds =     compsec_bprm_committed_creds,
  .bprm_secureexec =          compsec_bprm_secureexec,

  .sb_alloc_security =        compsec_sb_alloc_security,
  .sb_free_security =         compsec_sb_free_security,
  .sb_copy_data =             compsec_sb_copy_data,
  .sb_remount =               compsec_sb_remount,
  .sb_kern_mount =            compsec_sb_kern_mount,
  .sb_show_options =          compsec_sb_show_options,
  .sb_statfs =                compsec_sb_statfs,
  .sb_mount =                 compsec_mount,
  .sb_umount =                compsec_umount,
  .sb_set_mnt_opts =          compsec_set_mnt_opts,
  .sb_clone_mnt_opts =        compsec_sb_clone_mnt_opts,
  .sb_parse_opts_str =        compsec_parse_opts_str,


  .inode_alloc_security =     compsec_inode_alloc_security,
  .inode_free_security =      compsec_inode_free_security,
  .inode_init_security =      compsec_inode_init_security,
  .inode_create =             compsec_inode_create,
  .inode_link =               compsec_inode_link,
  .inode_unlink =             compsec_inode_unlink,
  .inode_symlink =            compsec_inode_symlink,
  .inode_mkdir =              compsec_inode_mkdir,
  .inode_rmdir =              compsec_inode_rmdir,
  .inode_mknod =              compsec_inode_mknod,
  .inode_rename =             compsec_inode_rename,
  .inode_readlink =           compsec_inode_readlink,
  .inode_follow_link =        compsec_inode_follow_link,
  .inode_permission =         compsec_inode_permission,
  .inode_setattr =            compsec_inode_setattr,
  .inode_getattr =            compsec_inode_getattr,
  .inode_setxattr =           compsec_inode_setxattr,
  .inode_post_setxattr =      compsec_inode_post_setxattr,
  .inode_getxattr =           compsec_inode_getxattr,
  .inode_listxattr =          compsec_inode_listxattr,
  .inode_removexattr =        compsec_inode_removexattr,
  .inode_getsecurity =        compsec_inode_getsecurity,
  .inode_setsecurity =        compsec_inode_setsecurity,
  .inode_listsecurity =       compsec_inode_listsecurity,
  .inode_getsecid =           compsec_inode_getsecid,

  .file_permission =          compsec_file_permission,
  .file_alloc_security =      compsec_file_alloc_security,
  .file_free_security =       compsec_file_free_security,
  .file_ioctl =               compsec_file_ioctl,
  .file_mmap =                compsec_file_mmap,
  .file_mprotect =            compsec_file_mprotect,
  .file_lock =                compsec_file_lock,
  .file_fcntl =               compsec_file_fcntl,
  .file_set_fowner =          compsec_file_set_fowner,
  .file_send_sigiotask =      compsec_file_send_sigiotask,
  .file_receive =             compsec_file_receive,

  .dentry_open =              compsec_dentry_open,

  .task_create =              compsec_task_create,
  .cred_alloc_blank =         compsec_cred_alloc_blank,
  .cred_free =                compsec_cred_free,
  .cred_prepare =             compsec_cred_prepare,
  .cred_transfer =            compsec_cred_transfer,
  .kernel_act_as =            compsec_kernel_act_as,
  .kernel_create_files_as =   compsec_kernel_create_files_as,
  .kernel_module_request =    compsec_kernel_module_request,
  .task_setpgid =             compsec_task_setpgid,
  .task_getpgid =             compsec_task_getpgid,
  .task_getsid =              compsec_task_getsid,
  .task_getsecid =            compsec_task_getsecid,
  .task_setnice =             compsec_task_setnice,
  .task_setioprio =           compsec_task_setioprio,
  .task_getioprio =           compsec_task_getioprio,
  .task_setrlimit =           compsec_task_setrlimit,
  .task_setscheduler =        compsec_task_setscheduler,
  .task_getscheduler =        compsec_task_getscheduler,
  .task_movememory =          compsec_task_movememory,
  .task_kill =                compsec_task_kill,
  .task_wait =                compsec_task_wait,
  .task_to_inode =            compsec_task_to_inode,

  .ipc_permission =           compsec_ipc_permission,
  .ipc_getsecid =             compsec_ipc_getsecid,

  .msg_msg_alloc_security =   compsec_msg_msg_alloc_security,
  .msg_msg_free_security =    compsec_msg_msg_free_security,

  .msg_queue_alloc_security = compsec_msg_queue_alloc_security,
  .msg_queue_free_security =  compsec_msg_queue_free_security,
  .msg_queue_associate =      compsec_msg_queue_associate,
  .msg_queue_msgctl =         compsec_msg_queue_msgctl,
  .msg_queue_msgsnd =         compsec_msg_queue_msgsnd,
  .msg_queue_msgrcv =         compsec_msg_queue_msgrcv,

  .shm_alloc_security =       compsec_shm_alloc_security,
  .shm_free_security =        compsec_shm_free_security,
  .shm_associate =            compsec_shm_associate,
  .shm_shmctl =               compsec_shm_shmctl,
  .shm_shmat =                compsec_shm_shmat,

  .sem_alloc_security =       compsec_sem_alloc_security,
  .sem_free_security =        compsec_sem_free_security,
  .sem_associate =            compsec_sem_associate,
  .sem_semctl =               compsec_sem_semctl,
  .sem_semop =                compsec_sem_semop,

  .d_instantiate =            compsec_d_instantiate,

  .getprocattr =              compsec_getprocattr,
  .setprocattr =              compsec_setprocattr,

  .secid_to_secctx =          compsec_secid_to_secctx,
  .secctx_to_secid =          compsec_secctx_to_secid,
  .release_secctx =           compsec_release_secctx,
  .inode_notifysecctx =       compsec_inode_notifysecctx,
  .inode_setsecctx =          compsec_inode_setsecctx,
  .inode_getsecctx =          compsec_inode_getsecctx,

  .unix_stream_connect =      compsec_socket_unix_stream_connect,
  .unix_may_send =            compsec_socket_unix_may_send,

  .socket_create =            compsec_socket_create,
  .socket_post_create =       compsec_socket_post_create,
  .socket_bind =              compsec_socket_bind,
  .socket_connect =           compsec_socket_connect,
  .socket_listen =            compsec_socket_listen,
  .socket_accept =            compsec_socket_accept,
  .socket_sendmsg =           compsec_socket_sendmsg,
  .socket_recvmsg =           compsec_socket_recvmsg,
  .socket_getsockname =       compsec_socket_getsockname,
  .socket_getpeername =       compsec_socket_getpeername,
  .socket_getsockopt =        compsec_socket_getsockopt,
  .socket_setsockopt =        compsec_socket_setsockopt,
  .socket_shutdown =          compsec_socket_shutdown,
  .socket_sock_rcv_skb =      compsec_socket_sock_rcv_skb,
  .socket_getpeersec_stream = compsec_socket_getpeersec_stream,
  .socket_getpeersec_dgram =  compsec_socket_getpeersec_dgram,
  .sk_alloc_security =        compsec_sk_alloc_security,
  .sk_free_security =         compsec_sk_free_security,
  .sk_clone_security =        compsec_sk_clone_security,
  .sk_getsecid =              compsec_sk_getsecid,
  .sock_graft =               compsec_sock_graft,
  .inet_conn_request =        compsec_inet_conn_request,
  .inet_csk_clone =           compsec_inet_csk_clone,
  .inet_conn_established =    compsec_inet_conn_established,
  .secmark_relabel_packet =   compsec_secmark_relabel_packet,
  .secmark_refcount_inc =     compsec_secmark_refcount_inc,
  .secmark_refcount_dec =     compsec_secmark_refcount_dec,
  .req_classify_flow =        compsec_req_classify_flow,
  .tun_dev_create =           compsec_tun_dev_create,
  .tun_dev_post_create =      compsec_tun_dev_post_create,
  .tun_dev_attach =           compsec_tun_dev_attach,

#ifdef CONFIG_KEYS
  .key_alloc =                compsec_key_alloc,
  .key_free =                 compsec_key_free,
  .key_permission =           compsec_key_permission,
  .key_getsecurity =          compsec_key_getsecurity,
#endif

};

static __init int compsec_init(void)
{
  // struct cred *cred;
	// struct unsigned int* initial_class;
  
  // // TODO: REMOVE BEFORE SUBMITTING
  // pr_info("Entered %s with pid %d\n", __func__, current->pid);

  if (!security_module_enable(&compsec_ops)) {
    printk("compsec: disabled at boot.\n");
    return 0;
  }

  if (register_security(&compsec_ops))
    panic("compsec: Unable to register compsec with kernel.\n");

  // initial_class = kzalloc(sizeof(struct file_accesses), GFP_ATOMIC); 
  // if (!initial_class)
  //   return -ENOMEM;

  // // TODO: REMOVE BEFORE SUBMITTING
  // pr_info("Succesfully allocated initial_class\n");

  // initial_class = COMPSEC_CLASS_UNCLASSIFIED;

	// cred = (struct cred *)current->cred;
	// cred->security = initial_class;

  printk("compsec: registered with the kernel\n");

  return 0;
}

static void __exit compsec_exit (void)
{  
  return;
}


module_init (compsec_init);
module_exit (compsec_exit);

/* MODULE_DESCRIPTION("compsec");
 * MODULE_LICENSE("GPL");
 */
#endif /* CONFIG_SECURITY_compsec */


