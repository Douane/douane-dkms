// Douane kernel module
// Copyright (C) 2013  Guillaume Hain <zedtux@zedroot.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION
#include <linux/netfilter.h>
// ~~~~ Due to bug https://bugs.launchpad.net/ubuntu/+source/linux/+bug/929715 ~~~~
// #undef __KERNEL__
// #include <linux/netfilter_ipv4.h> // NF_IP_POST_ROUTING, NF_IP_PRI_LAST
// #define __KERNEL__
#define NF_IP_LOCAL_OUT 3
enum nf_ip_hook_priorities {
  NF_IP_PRI_LAST = INT_MAX
};
// ~~~~
#include <linux/netfilter.h>      // nf_register_hook(), nf_unregister_hook()
#include <linux/netlink.h>        // NLMSG_SPACE(), nlmsg_put(), NETLINK_CB(), NLMSG_DATA(), NLM_F_REQUEST, netlink_unicast(), netlink_kernel_release(), nlmsg_hdr(), NETLINK_USERSOCK, netlink_kernel_create()
#include <linux/sched.h>          // for_each_process(), task_lock(), task_unlock()
#include <linux/ip.h>             // ip_hdr()
#include <linux/udp.h>            // udp_hdr()
#include <linux/tcp.h>            // tcp_hdr()
#include <linux/fdtable.h>        // files_fdtable(), fcheck_files()
#include <linux/list.h>           // INIT_LIST_HEAD(), list_for_each_entry(), list_add_tail(), list_empty(), list_entry(), list_del(), list_for_each_entry_safe()
#include <linux/dcache.h>         // d_path()
#include <linux/skbuff.h>         // alloc_skb()
#include <linux/pid_namespace.h>  // task_active_pid_ns()
#include <linux/rculist.h>        // hlist_for_each_entry_rcu

#include "network_activity_message.h"

#ifndef DOUANE_VERSION
#define DOUANE_VERSION "UNKNOWN"
#endif

MODULE_DESCRIPTION("Douane");
MODULE_AUTHOR("Guillaume Hain <zedtux@zedroot.org>");
MODULE_VERSION(DOUANE_VERSION);
MODULE_LICENSE("GPL");


#define PATH_LENGTH 129
// Limit of fd not found before to switch to the next process
#define MAX_FD_NULL 9

/*
** Helpers
*/
static int index_of(const char * base, const char * str)
{
    int result;
    int baselen = strlen(base);
    char * pos = NULL;

    // str should not longer than base
    if (strlen(str) > baselen)
        result = -1;
    else {
        pos = strstr(base, str);
        result = ((pos == NULL) ? -1 : (pos - base));
    }
    return result;
}


/*
**  Module internal rules management
*/
struct rule
{
  char              process_path[PATH_LENGTH];
  bool              allowed;
  struct list_head  list;
};
struct rule rules;
#ifdef DEBUG
int rules_count = 0;


static void print_rules(void)
{
  struct rule * current_rule;

  printk(KERN_ERR "douane:%d:%s: Currently %d rules are regisered.\n", __LINE__, __FUNCTION__, rules_count);

  // Iterate over all registered rules
  list_for_each_entry(current_rule, &(rules.list), list)
  {
    if (current_rule->allowed)
    {
      printk(KERN_INFO "douane:%d:%s: process_path %s is allowed.\n", __LINE__, __FUNCTION__, current_rule->process_path);
    } else {
      printk(KERN_INFO "douane:%d:%s: process_path %s is disallowed.\n", __LINE__, __FUNCTION__, current_rule->process_path);
    }
  }
}
#endif

static void append_rule(const char * process_path, const bool is_allowed)
{
  struct rule * new_rule;

  // Don't do anything if passed process_path is NULL
  if (process_path == NULL)
    return;

  new_rule = (struct rule *)kmalloc(sizeof(struct rule), GFP_ATOMIC);
  if(new_rule == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: Failed to allocate new rule.\n", __LINE__, __FUNCTION__);
    return;
  }

  // Copy the passed path in the rule
  strcpy(new_rule->process_path, process_path);
  new_rule->allowed = is_allowed;
  // Add the rule to the linked list
  list_add_tail(&(new_rule->list), &(rules.list));
#ifdef DEBUG
  // Update rules counter
  rules_count++;
#endif

#ifdef DEBUG
  if (new_rule->allowed)
  {
    printk(KERN_INFO "douane:%d:%s: New rule of type ALLOW added for %s\n", __LINE__, __FUNCTION__, new_rule->process_path);
  } else {
    printk(KERN_INFO "douane:%d:%s: New rule of type DISALLOW added for %s\n", __LINE__, __FUNCTION__, new_rule->process_path);
  }
  print_rules();
#endif
}

static void clear_rules(void)
{
  struct rule * iter;

  // Iterate over each rules
  while(!list_empty(&rules.list))
  {
    // Get an iterator
    iter = list_entry(rules.list.next, struct rule, list);
    // Remove the rule
    list_del(&iter->list);
    // Delete the iterator
    kfree(iter);
  }

#ifdef DEBUG
  // Reset rules counter
  rules_count = 0;
  printk(KERN_INFO "douane:%d:%s: Rules successfully cleaned.\n", __LINE__, __FUNCTION__);
#endif
}

static void remove_rule_from_path(const unsigned char * process_path)
{
  struct rule * rule_a, * rule_b;

  // Don't do anything if passed process_path is NULL
  if (process_path == NULL)
    return;

#ifdef DEBUG
  printk(KERN_INFO "douane:%d:%s: Deleting rule for path %s.\n", __LINE__, __FUNCTION__, process_path);
#endif

  // Iterate over all registered rules
  list_for_each_entry_safe(rule_a, rule_b, &(rules.list), list)
  {
    // Compare current rule process_path with the passed one
    if (strcmp(rule_a->process_path, process_path) == 0)
    {
      // If found delete the rule from the linked list
      list_del(&rule_a->list);
      // Free the pointer to the rule
      kfree(rule_a);
#ifdef DEBUG
      // Update rules counter
      rules_count--;
#endif
    }
  }
}

static struct rule * search_rule_for_process_path(const unsigned char * process_path)
{
  struct rule * current_rule;

  // Don't do anything if passed process_path is NULL
  if (process_path == NULL)
    return NULL;

  // Iterate over all registered rules
  list_for_each_entry(current_rule, &(rules.list), list)
  {
    // Compare current rule process_path with the passed one
    if (strcmp(current_rule->process_path, process_path) == 0)
    {
#ifdef DEBUG
      if (current_rule->allowed)
      {
        printk(KERN_INFO "douane:%d:%s: Rule ALLOW found for %s.\n", __LINE__, __FUNCTION__, current_rule->process_path);
      } else {
        printk(KERN_INFO "douane:%d:%s: Rule DISALLOW found for %s.\n", __LINE__, __FUNCTION__, current_rule->process_path);
      }
#endif
      // Return the rule when found (Stop the loop)
      return current_rule;
    }
  }

  // Otherwise return a NULL (Rule not found)
  return NULL;
}



/*
**  Module process detection
*/
struct process_socket_inode
{
  unsigned long i_ino;                      // Process socket file inode
  pid_t         pid;                        // PID of the process
  char          process_path[PATH_LENGTH];  // Path of the process
  uint32_t      sequence;                   // TCP sequence (Is be 0 for non TCP packets)
  struct        list_head list;
};
struct process_socket_inode process_socket_inodes;


static void remember_process_socket_inode(const pid_t pid, const uint32_t sequence, const unsigned long i_ino, const char * path)
{
  struct process_socket_inode * new_process_socket_inode;
  struct process_socket_inode * process_socket_inode_a, * process_socket_inode_b; // For garbage collector
  int                           process_cleaned_records = 0;

  if (pid == 0 || i_ino == 0 || path == NULL)
    return;

  /*
  ** In order to clean this linked list, before saving the new relation process <-> socket file
  *  we first look if there are records for the given PID with a different path.
  *  If this is the case it means that it is a new process that own the given PID so previous records can be cleaned
  */
  list_for_each_entry_safe(process_socket_inode_a, process_socket_inode_b, &(process_socket_inodes.list), list)
  {
    if (process_socket_inode_a->pid == pid && strcmp(process_socket_inode_a->process_path, path) != 0)
    {
#ifdef DEBUG
      printk(KERN_INFO "douane:%d:%s: The process path %s relates to PID %d but is now %s.\n", __LINE__, __FUNCTION__, process_socket_inode_a->process_path, process_socket_inode_a->pid, path);
#endif
      list_del(&process_socket_inode_a->list);
      kfree(process_socket_inode_a);

      process_cleaned_records++;
    }
  }

#ifdef DEBUG
  if (process_cleaned_records > 0)
  {
    printk(KERN_INFO "douane:%d:%s: %d process <-> socket file relations have been deleted.\n", __LINE__, __FUNCTION__, process_cleaned_records);
  }
#endif

  /*
  ** Now save the new entry for the new application
  */
  new_process_socket_inode = (struct process_socket_inode *)kmalloc(sizeof(struct process_socket_inode), GFP_ATOMIC);
  if(new_process_socket_inode == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: Failed to allocate new process_socket_inode.\n", __LINE__, __FUNCTION__);
    return;
  }

  new_process_socket_inode->i_ino = i_ino;
  new_process_socket_inode->pid = pid;
  new_process_socket_inode->sequence = sequence;
  strcpy(new_process_socket_inode->process_path, path);

  list_add_tail(&(new_process_socket_inode->list), &(process_socket_inodes.list));
}

static void forget_process_socket_inode(const pid_t pid, const unsigned long i_ino)
{
  struct process_socket_inode * process_socket_inode_a, * process_socket_inode_b;

  if (pid == 0 || i_ino == 0)
    return;

  list_for_each_entry_safe(process_socket_inode_a, process_socket_inode_b, &(process_socket_inodes.list), list)
  {
    if (process_socket_inode_a->pid == pid && process_socket_inode_a->i_ino == i_ino)
    {
      list_del(&process_socket_inode_a->list);
      kfree(process_socket_inode_a);
    }
  }
}

static void update_task_info_sequence(const unsigned long i_ino, const uint32_t sequence)
{
  struct process_socket_inode * current_process_socket_inode;

  if (i_ino != 0)
  {
    list_for_each_entry(current_process_socket_inode, &(process_socket_inodes.list), list)
    {
      if (current_process_socket_inode->i_ino == i_ino)
      {
        current_process_socket_inode->sequence = sequence;
      }
    }
  }
}

static struct process_socket_inode * task_info_from_open_file_inode(const unsigned long i_ino)
{
  struct process_socket_inode * current_process_socket_inode;

  if (i_ino == 0)
    return NULL;

  list_for_each_entry(current_process_socket_inode, &(process_socket_inodes.list), list)
  {
    if (current_process_socket_inode->i_ino == i_ino)
      return current_process_socket_inode;
  }

  return NULL;
}

static struct process_socket_inode * task_info_from_sequence(const uint32_t sequence)
{
  struct process_socket_inode * current_process_socket_inode;

  if (sequence == 0)
    return NULL;

  list_for_each_entry(current_process_socket_inode, &(process_socket_inodes.list), list)
  {
    if (current_process_socket_inode->sequence > 0)
    {
      if (current_process_socket_inode->sequence == sequence || ((current_process_socket_inode->sequence + 1) == sequence))
      {
        return current_process_socket_inode;
      }
    }
  }

  return NULL;
}

static void clear_process_socket_inodes(void)
{
  struct process_socket_inode * iter;
  int                           process_cleaned_records = 0;

  while(!list_empty(&process_socket_inodes.list))
  {
    iter = list_entry(process_socket_inodes.list.next, struct process_socket_inode, list);
    list_del(&iter->list);
    kfree(iter);

    process_cleaned_records++;
  }
#ifdef DEBUG
  printk(KERN_INFO "douane:%d:%s: %d relations process <-> socket file successfully cleaned.\n", __LINE__, __FUNCTION__, process_cleaned_records);
#endif
}


/*
**  Global module memory helper methods
*/
static void blackout(void)
{
  clear_process_socket_inodes();
  clear_rules();
}

/*
** Netlink: Communications with user namespace
*/
static struct sock *  activities_socket = NULL; // Netfilter socket to send network activities and recieve orders from the user space daemon
pid_t                 daemon_pid;               // User space running daemon

// Push in the Netlink socket the network activity to send it to the daemon
static int push(const struct network_activity *activity)
{
  struct nlmsghdr * nlh;
  struct sk_buff *  skb = NULL;
  int               ret = 0;

  // If no process_path don't send the network_activity message to the daemon
  if (activity->process_path == NULL || strcmp(activity->process_path, "") == 0)
  {
    printk(KERN_ERR "douane:%d:%s: BLOCKED PUSH: process_path is blank.\n", __LINE__, __FUNCTION__);
    return 0;
  }

  skb = alloc_skb(NLMSG_SPACE(sizeof(struct network_activity)), GFP_ATOMIC);
  if (skb == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: BLOCKED PUSH: Failed to allocate new socket buffer.\n", __LINE__, __FUNCTION__);
    return -1;
  }

  nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct network_activity), 0);
  if (nlh == NULL)
  {
    if (skb)
      kfree_skb(skb);
    printk(KERN_ERR "douane:%d:%s: BLOCKED PUSH: nlmsg_put failed.\n", __LINE__, __FUNCTION__);
    return -1;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
  NETLINK_CB(skb).portid = 0; /* from kernel */
#else
  NETLINK_CB(skb).pid = 0; /* from kernel */
#endif
  memcpy(NLMSG_DATA(nlh), activity, sizeof(struct network_activity));

  nlh->nlmsg_flags = NLM_F_REQUEST; // Must be set on all request messages.

  if (activities_socket == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: BLOCKED PUSH: Socket not connected!!.\n", __LINE__, __FUNCTION__);
    return -1;
  }

  // netlink_unicast() takes ownership of the skb and frees it itself.
  ret = netlink_unicast(activities_socket, skb, daemon_pid, MSG_DONTWAIT);
  if (ret < 0)
  {
    if (ret == -11)
    {
      printk(KERN_WARNING "douane:%d:%s: Message ignored as Netfiler socket is busy.\n", __LINE__, __FUNCTION__);
    } else {
      printk(KERN_ERR "douane:%d:%s: Failed to send message (errno: %d).\n", __LINE__, __FUNCTION__, ret);
      daemon_pid = 0;
      blackout();
    }
    return ret;
  } else {
    return 0;
  }
}

static int initialize_activities_socket(void);

static void terminate_activities_connection(void)
{
  // No more try to push rules to the daemon
  daemon_pid = 0;

  // Allow all applications to connect outside
  blackout();
}

// Reset sockets after an error or on unload of the module
static void reset_netlink_sockets(void)
{
  if (activities_socket)
  {
#ifdef DEBUG
    printk(KERN_INFO "douane:%d:%s: Shutting down activities Netlink socket...\n", __LINE__, __FUNCTION__);
#endif
    netlink_kernel_release(activities_socket);
    activities_socket = NULL;
  }

  terminate_activities_connection();
  initialize_activities_socket();
}

/*
**  Netlink socket handlers
*/
static void activities_socket_receiver(struct sk_buff *skb)
{
  struct nlmsghdr *         nlh = nlmsg_hdr(skb);
  struct network_activity * activity = NLMSG_DATA(nlh);
  struct rule *             new_rule = NULL;

  if (activity == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: Can't allocate memory for a new activity\n", __LINE__, __FUNCTION__);
    return;
  }

  // Activity kind must be positive number
  if (activity->kind <= 0)
  {
    printk(KERN_ERR "douane:%d:%s: Invalid received message. (No kind)\n", __LINE__, __FUNCTION__);
    reset_netlink_sockets();
    return;
  }

  // Do actions based on the kind
  switch(activity->kind)
  {
    // Opening connection to the LKM
    case KIND_HAND_CHECK:
    {
      daemon_pid = nlh->nlmsg_pid;
#ifdef DEBUG
      printk(KERN_INFO "douane:%d:%s: Process %d successfully registered.\n", __LINE__, __FUNCTION__, daemon_pid);
#endif
    }
    break;

    // Adding new rule to the LKM (used after connection hand check to load rules)
    case KIND_SENDING_RULE:
    {
      // Lookup for an exiting rule
      new_rule = search_rule_for_process_path(activity->process_path);
      // No rule found for the process path
      if (new_rule == NULL)
      {
        // Create the new rule
        append_rule(activity->process_path, (activity->allowed == 1));
      }
    }
    break;

    // Delete a rule
    case KIND_DELETE_RULE:
    {
      remove_rule_from_path(activity->process_path);
#ifdef DEBUG
      printk(KERN_INFO "douane:%d:%s: Rule deleted\n", __LINE__, __FUNCTION__);
#endif
    }
    break;

    // Disconnecting from the LKM (properly)
    case KIND_GOODBYE:
    {
      terminate_activities_connection();
    }
    break;

    // All other kinds
    default:
    {
      printk(KERN_ERR "douane:%d:%s: Invalid received message. (Unknown kind)\n", __LINE__, __FUNCTION__);
      // Disconnect the userspace process that send a wrong message
      reset_netlink_sockets();
    }
    break;
  }
}

/*
**  Netlink socket initializer
*/
static int initialize_activities_socket(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
  struct netlink_kernel_cfg cfg =
  {
    .input = activities_socket_receiver,
  };
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
  activities_socket = netlink_kernel_create(&init_net,
                        NETLINK_USERSOCK,
                        &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
  activities_socket = netlink_kernel_create(&init_net,
                        NETLINK_USERSOCK,
                        THIS_MODULE,
                        &cfg);
#else
  activities_socket = netlink_kernel_create(&init_net,
                        NETLINK_USERSOCK,
                        0,
                        activities_socket_receiver,
                        NULL,
                        THIS_MODULE);
#endif
  if (activities_socket == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: Can't create Netlink socket for network activities!\n", __LINE__, __FUNCTION__);
    return -ENOMEM;
  }

  return 0;
}

/*
**  Relation packet <-> process helper methods
*/
static bool task_has_open_file(const struct task_struct * task, const struct file * socket_file)
{
  struct file * file = NULL;
  int           fd_i = 0;
  int           fd_null = 0;
  int           fd_null_max = 0;
  bool          iterating_fd = true;

  if (task == NULL)
    return false;

  if (task->files == NULL)
    return false;

  while (iterating_fd)
  {
    file = fcheck_files(task->files, fd_i);
    if (file)
    {
      /*
      ** In order to avoid going through all the fds of a process
      *  the fd_null variable is used to define a limit.
      *  This allows Douane to ignore processes which aren't owning the fd
      *  and switch to the next process, so Douane is faster.
      *
      *  But this limit can make Douane blind and will never find the process.
      *  In order to highligh this, the fd_null_max variable, which is printed
      *  in the logs in debug mode, shows the correct number for the current
      *  process.
      *
      *  For example, with Ubuntu <= 13.10, the correct value for fd_null is 3,
      *  while now with Ubuntu 14.04, the correct value for fd_null is around 8.
      */
      if (fd_null > fd_null_max)
        fd_null_max = fd_null;

      fd_null = 0;

      if (S_ISSOCK(file->f_path.dentry->d_inode->i_mode))
      {
        if (file == socket_file)
        {
#ifdef DEBUG
          printk(KERN_INFO "douane:%d:%s: fd_null_max: %d | MAX_FD_NULL: %d\n",
            __LINE__, __FUNCTION__, fd_null_max, MAX_FD_NULL);
#endif
          return true;
        }
      }
    } else {
      fd_null++;

      if (fd_null >= MAX_FD_NULL)
        iterating_fd = 0;
    }

    fd_i++;
  }

  return false;
}

static char * task_exe_path(struct task_struct * task, char * buff)
{
  struct task_struct *  locked_task = task;
  char                  tmpbuf[PATH_LENGTH];
  int                   deleted_position;

  if (task == NULL)
    return NULL;

  rcu_read_lock();

  do
  {
    task_lock(locked_task);

    if (likely(locked_task->mm))
    {
      if (locked_task->mm->exe_file)
      {
        // Get process path using d_path()
        // d_path() suffix the path with " (deleted)" when the file is still accessed
        // and the deletion of the file has been requested.
        strcpy(buff, d_path(&locked_task->mm->exe_file->f_path, tmpbuf, PATH_LENGTH));

        task_unlock(locked_task);

        // Remove the deleted suffix if present
        if ((deleted_position = index_of(buff, " (deleted)")) > 0)
        {
          // Clean temp buffer in order to reuse it
          memset(&tmpbuf[0], 0, PATH_LENGTH);
          // Copy the current buffer in the temp buffer
          strcpy(tmpbuf, buff);
          // Clean the current buffer
          memset(&buff[0], 0, PATH_LENGTH);
          // Copy the path without the " (deleted)" suffix
          strncpy(buff, tmpbuf, deleted_position);
        }

        break;
      }
    }

    task_unlock(locked_task);

  } while_each_thread(task, locked_task);

  rcu_read_unlock();

  return buff;
}

static struct task_struct * find_task_from_socket_file(struct file * socket_file)
{
  struct task_struct *  task;

  rcu_read_lock();
  for_each_process(task)
  {
    rcu_read_unlock();

    get_task_struct(task);

    if (task_has_open_file(task, socket_file))
      return task;

    rcu_read_lock();
  }
  rcu_read_unlock();

  return NULL;
}

#ifdef DEBUG
static void print_tcp_packet(const struct tcphdr * tcp_header, const struct iphdr * ip_header, char * ip_source, char * ip_destination, char * process_path)
{
  if (tcp_header)
  {
    printk(KERN_INFO "douane:%d:%s: TCP | [seq:%u|ack_seq:%u]\tFLAGS=%c%c%c%c%c%c | TGID %d:\t%s:%hu --> %s:%hu (%s|%s) {W:%hu|%d} %s.\n", __LINE__, __FUNCTION__,
      ntohl(tcp_header->seq),
      ntohl(tcp_header->ack_seq),
      tcp_header->urg ? 'U' : '-',
      tcp_header->ack ? 'A' : '-',
      tcp_header->psh ? 'P' : '-',
      tcp_header->rst ? 'R' : '-',
      tcp_header->syn ? 'S' : '-',
      tcp_header->fin ? 'F' : '-',
      current->tgid,
      ip_source,
      ntohs(tcp_header->source),
      ip_destination,
      ntohs(tcp_header->dest),
      process_path,
      current->comm,
      ntohs(tcp_header->window),
      ntohs(ip_header->tot_len) - (tcp_header->doff * 4) - (ip_header->ihl * 4),
      "NF_ACCEPT"
    );
  }
}
#endif

/*
**  Netfiler hook
*/
static unsigned int netfiler_packet_hook(unsigned int hooknum,
                     struct sk_buff *skb,
                     const struct net_device *in,
                     const struct net_device *out,
                     int (*okfn) (struct sk_buff *))
{
  struct iphdr *                ip_header = NULL;
  struct udphdr *               udp_header = NULL;
  struct tcphdr *               tcp_header = NULL;
  struct network_activity *     activity = (struct network_activity*) kmalloc(sizeof(struct network_activity), GFP_ATOMIC);
  struct rule *                 rule = NULL;
  struct task_struct *          task = NULL;
  struct task_struct *          task_with_open_file = NULL;
  struct process_socket_inode * task_info = NULL;
  char                          ip_source[16];
  char                          ip_destination[16];
  char                          process_owner_path[PATH_LENGTH] = "";
  char                          buffer[PATH_LENGTH] = "";
  int                           sport = 0;
  int                           dport = 0;
  int                           task_has_file_opened = 0;
  unsigned long                 socket_file_ino;
  bool                          filterable = false;
  bool                          known_protocol = false;
  bool                          lookup_from_socket_sequence = false;

  if (activity == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: Can't allocate memory for a new activity\n", __LINE__, __FUNCTION__);
    return -ENOMEM;
  }

  // Empty socket buffer
  if (skb == NULL)
  {
    printk(KERN_WARNING "douane:%d:%s: Allowing traffic as socket buffer is NULL.\n", __LINE__, __FUNCTION__);
    kfree(activity);
    return NF_ACCEPT;
  }

  /*
  **  Network informations
  *
  *  Using IP/TCP/UDP headers find source and destination IP addresses
  *  ports, size etc...
  */
  // Retrieve IP information (Source and Destination IP/port)
  ip_header = ip_hdr(skb);
  if (ip_header == NULL)
  {
    printk(KERN_ERR "douane:%d:%s: !!OOPS!! ip_header is NULL. !!OOPS!!\n", __LINE__, __FUNCTION__);
    kfree(activity);
    return NF_ACCEPT;
  }

  // Convert to string IP addresses
  snprintf(ip_source, 16, "%pI4", &ip_header->saddr);
  snprintf(ip_destination, 16, "%pI4", &ip_header->daddr);

  // Based on the packet protocol
  switch(ip_header->protocol)
  {
    // UDP
    case IPPROTO_UDP:
    {
      // Getting UDP header
      udp_header = udp_hdr(skb);
      if (udp_header == NULL)
      {
        printk(KERN_ERR "douane:%d:%s: !!OOPS!! udp_header is NULL. !!OOPS!!\n", __LINE__, __FUNCTION__);
        return NF_ACCEPT;
      }
      // Getting source and destination ports
      sport = (unsigned int) ntohs(udp_header->source);
      dport = (unsigned int) ntohs(udp_header->dest);

      known_protocol = true;
      break;
    }

    // TCP
    case IPPROTO_TCP:
    {
      // Getting TCP header
      tcp_header = tcp_hdr(skb);
      if (tcp_header == NULL)
      {
        printk(KERN_ERR "douane:%d:%s: !!OOPS!! tcp_header is NULL. !!OOPS!!\n", __LINE__, __FUNCTION__);
        return NF_ACCEPT;
      }
      // Getting source and destination ports
      sport = (unsigned int) ntohs(tcp_header->source);
      dport = (unsigned int) ntohs(tcp_header->dest);

      known_protocol = true;
      break;
    }

    // All otherss
    default:
    {
#ifdef DEBUG
      printk(KERN_INFO "douane:%d:%s: [UNKOWN(%d)] %s -> %s\n", __LINE__, __FUNCTION__,
        ip_header->protocol,
        ip_source,
        ip_destination);
#endif
      kfree(activity);
      return NF_ACCEPT;
    }
  }

  /*
  **  Process informations
  *
  *   Using the socket file we're going through each running processes
  *   and compare the socket file to the process opened files.
  *   Creating a socket in the userspace create a file that is added
  *   in the list of process opened files (On Linux everything is a file).
  */
  if (skb->sk)
  {
    if (skb->sk->sk_socket)
    {
      if (skb->sk->sk_socket->file)
      {
        /*
        ** The current packet is filterable as we have the socket file
        */
        filterable = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
        socket_file_ino = skb->sk->sk_socket->file->f_inode->i_ino;
#else
        socket_file_ino = skb->sk->sk_socket->file->f_dentry->d_inode->i_ino;
#endif

        task_info = task_info_from_open_file_inode(socket_file_ino);
        if (task_info)
        {
          if (tcp_header)
            update_task_info_sequence(socket_file_ino, ntohl(tcp_header->seq));

          task = get_pid_task(find_get_pid(task_info->pid), PIDTYPE_PID);
          if (task)
          {
            rcu_read_lock();
            task_has_file_opened = task_has_open_file(task, skb->sk->sk_socket->file);
            rcu_read_unlock();

            if (task_has_file_opened)
            {
              strcpy(process_owner_path, task_info->process_path);
            } else {
              // For all non TCP packet and for TCP packet (except packets flaged as FIN)
              if (tcp_header == NULL || (tcp_header && tcp_header->fin == false))
              {
                task_with_open_file = find_task_from_socket_file(skb->sk->sk_socket->file);
                if (task_with_open_file)
                {
                  // The task is no more owning the passed socket file
                  // so we can forget the relation task <-> socket file
                  forget_process_socket_inode(task->pid, socket_file_ino);

                  strcpy(process_owner_path, task_exe_path(task_with_open_file, buffer));

                  if (tcp_header)
                  {
                    // Remember relation task <-> socket file
                    remember_process_socket_inode(task_with_open_file->pid, ntohl(tcp_header->seq), socket_file_ino, process_owner_path);
                  } else {
                    // Remember relation task <-> socket file
                    remember_process_socket_inode(task_with_open_file->pid, 0, socket_file_ino, process_owner_path);
                  }
                } else {
                  // The current packet is a ACK packet after a FIN
                  strcpy(process_owner_path, task_info->process_path);
                }
              // Only for TCP packets flaged as FIN
              } else {
                strcpy(process_owner_path, task_info->process_path);
              }
            }
#ifdef DEBUG
          } else {
            // Task no more exists
            printk(KERN_INFO "douane:%d:%s: !!OOO!! Task no more exists. !!OOO!!\n", __LINE__, __FUNCTION__);
#endif
          }
        } else {
          task = find_task_from_socket_file(skb->sk->sk_socket->file);
          if (task)
          {
            strcpy(process_owner_path, task_exe_path(task, buffer));
            if (tcp_header)
            {
              // Remember relation task <-> socket file
              remember_process_socket_inode(task->pid, ntohl(tcp_header->seq), socket_file_ino, process_owner_path);
            } else {
              // Remember relation task <-> socket file
              remember_process_socket_inode(task->pid, 0, socket_file_ino, process_owner_path);
            }
#ifdef DEBUG
          } else {
            printk(KERN_WARNING "douane:%d:%s: !!OOPS!! Don't know and can't find a task for socket file inode number %ld !!OOPS!!\n", __LINE__, __FUNCTION__, socket_file_ino);
#endif
          }
        }

      } else {
#ifdef DEBUG
        printk(KERN_WARNING "douane:%d:%s: !!WARN WARN WARN!! skb->sk->sk_socket->file is NULL. !!WARN WARN WARN!!\n", __LINE__, __FUNCTION__);
#endif
        lookup_from_socket_sequence = true;
      }
    } else {
#ifdef DEBUG
      printk(KERN_WARNING "douane:%d:%s: !!WARN WARN WARN!! skb->sk->sk_socket is NULL. !!WARN WARN WARN!!\n", __LINE__, __FUNCTION__);
#endif
      lookup_from_socket_sequence = true;
    }
  } else {
#ifdef DEBUG
    printk(KERN_WARNING "douane:%d:%s: !!WARN WARN WARN!! skb->sk is NULL. !!WARN WARN WARN!!\n", __LINE__, __FUNCTION__);
#endif
    lookup_from_socket_sequence = true;
  }

  if (lookup_from_socket_sequence)
  {
    if (tcp_header)
    {
      task_info = task_info_from_sequence(ntohl(tcp_header->seq));
      if (task_info)
      {
        strcpy(process_owner_path, task_info->process_path);
#ifdef DEBUG
      } else {
        printk(KERN_ERR "douane:%d:%s: !!OOPS!! skb->sk->sk_socket or skb->sk is NULL and nothing found from sequence %u. !!OOPS!!\n", __LINE__, __FUNCTION__, ntohl(tcp_header->seq));
#endif
      }
#ifdef DEBUG
    } else {
      printk(KERN_ERR "douane:%d:%s: !!OOPS!! lookup_from_socket_sequence but wasn't a TCP packet! !!OOPS!!\n", __LINE__, __FUNCTION__);
#endif
    }
  }

#ifdef DEBUG
  print_tcp_packet(tcp_header, ip_header, ip_source, ip_destination, process_owner_path);
#endif

  // When was filterable but didn't got process path
  if (filterable && (process_owner_path == NULL || strcmp(process_owner_path, "") == 0))
  {
    kfree(activity);
#ifdef DEBUG
    printk(KERN_INFO "douane:%d:%s: !!OOPS!! process_owner_path is blank but was filterable! !!OOPS!!\n", __LINE__, __FUNCTION__);
#endif
    return NF_ACCEPT;
  }


  /*
  **  Ignore the packet if:
  *  - daemon not connected
  *  - daemon process has PID 0
  */
  if (activities_socket == NULL || daemon_pid == 0)
  {
    kfree(activity);
#ifdef DEBUG
    printk(KERN_INFO "douane:%d:%s: NF_ACCEPT (No daemon).\n", __LINE__, __FUNCTION__);
#endif
    return NF_ACCEPT;
  }


  /*
  **  Building new network_activity message
  */
  strcpy(activity->process_path, process_owner_path);
  strcpy(activity->devise_name, out->name);
  activity->protocol = ip_header->protocol;
  strcpy(activity->ip_source, ip_source);
  activity->port_source = sport;
  strcpy(activity->ip_destination, ip_destination);
  activity->port_destination = dport;
  activity->size = skb->len;

  // Push the activity to the daemon process
  if (push(activity) < 0)
    printk(KERN_ERR "douane:%d:%s: Something prevent to sent the network activity.\n", __LINE__, __FUNCTION__);

  kfree(activity);

  rule = search_rule_for_process_path(process_owner_path);
  if (filterable)
  {
    if (rule == NULL)
    {
#ifdef DEBUG
      printk(KERN_INFO "douane:%d:%s: NF_QUEUE for %s as no rules yet.\n", __LINE__, __FUNCTION__, process_owner_path);
#endif
      return NF_QUEUE;
    } else {
      if (rule->allowed)
      {
#ifdef DEBUG
        printk(KERN_INFO "douane:%d:%s: NF_ACCEPT for %s as allowed.\n", __LINE__, __FUNCTION__, process_owner_path);
#endif
        return NF_ACCEPT;
      } else {
#ifdef DEBUG
        printk(KERN_INFO "douane:%d:%s: NF_DROP for %s as disallowed.\n", __LINE__, __FUNCTION__, process_owner_path);
#endif
        return NF_DROP;
      }
    }
  } else {
#ifdef DEBUG
    printk(KERN_INFO "douane:%d:%s: NF_ACCEPT for %s as not filterable.\n", __LINE__, __FUNCTION__, process_owner_path);
#endif
    return NF_ACCEPT;
  }
}


/*
**  Netfiler hook
*/
static struct nf_hook_ops nfho_outgoing = {
  .hook     = netfiler_packet_hook,
  .hooknum  = NF_IP_LOCAL_OUT,
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_LAST,
  .owner    = THIS_MODULE
};


/*
** Linux kernel module initializer and cleaner methods
*/
static int __init initialize_module(void)
{
#ifdef DEBUG
  printk(KERN_INFO "douane:%d:%s: Initializing module\n", __LINE__, __FUNCTION__);
#endif
  INIT_LIST_HEAD(&rules.list);
  INIT_LIST_HEAD(&process_socket_inodes.list);

  // Hook to Netfilter
  nf_register_hook(&nfho_outgoing);

  // Open a Netfilter socket to communicate with the user space
  if (initialize_activities_socket() < 0)
  {
    printk(KERN_ERR "douane:%d:%s: Unable to create Netlink socket!\n", __LINE__, __FUNCTION__);
    return -1;
  }

#ifdef DEBUG
  printk(KERN_INFO "douane:%d:%s: Kernel module is ready!\n", __LINE__, __FUNCTION__);
#else
  printk(KERN_INFO "douane: Kernel module loaded\n");
#endif
  return 0;
}
static void __exit exit_module(void)
{
  reset_netlink_sockets();
  if (activities_socket)
  {
#ifdef DEBUG
    printk(KERN_INFO "douane:%d:%s: Shutting down activities Netlink socket...\n", __LINE__, __FUNCTION__);
#endif
    netlink_kernel_release(activities_socket);
    activities_socket = NULL;
  }

  nf_unregister_hook(&nfho_outgoing);

#ifdef DEBUG
  printk(KERN_INFO "douane:%d:%s: Kernel module removed!\n", __LINE__, __FUNCTION__);
#else
  printk(KERN_INFO "douane: Kernel module unloaded\n");
#endif
}

// Boot the Douane Linux Kernel Module
module_init(initialize_module);
module_exit(exit_module);
