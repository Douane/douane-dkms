/*
** This file is a common file for Kernel and user space.
*
*  It describe the message that is passed from Kernel module to user space daemon process.
*/

// Possible action kinds
#define KIND_HAND_CHECK   1
#define KIND_SENDING_RULE 2
#define KIND_GOODBYE      3
#define KIND_DELETE_RULE  4

/*
**  Douane network activity message
*/
struct network_activity {
  int   kind;                       // Deamon -> LKM  | Define which kind of message it is
  char  process_path[PATH_MAX * 4]; // Bidirectional  | Related process path
  int   allowed;                    // Deamon -> LKM  | Define if the process is allowed to outgoing network traffic or not
  char  devise_name[16];            // Bidirectional  | Device name where the packet has been detected (IFNAMSIZ = 16)
  int   protocol;                   // LKM -> Deamon  | Protocol id of the detected outgoing network activity
  char  ip_source[16];              // LKM -> Deamon  | Outgoing network traffic ip source
  int   port_source;                // LKM -> Deamon  | Outgoing network traffic port source
  char  ip_destination[16];         // LKM -> Deamon  | Outgoing network traffic ip destination
  int   port_destination;           // LKM -> Deamon  | Outgoing network traffic port destination
  int   size;                       // LKM -> Deamon  | Size of the packet
};

/*
**  This network_activity message is used in both ways:
*     - From Kernel to User space in order to forward network activities
*     - From User space to Kernel in order to send rules
*/
