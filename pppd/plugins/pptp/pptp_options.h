/* pptp_options.h ...... various constants used in the PPTP protocol.
 *                       C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: pptp_options.h,v 1.3 2004/11/09 01:42:32 quozl Exp $
 */

#ifndef INC_PPTP_OPTIONS_H
#define INC_PPTP_OPTIONS_H

#define PPTP_TIMEOUT 60 /* seconds */
extern int idle_wait;
extern int max_echo_wait;
#define PPTP_CONNECT_SPEED 1000000000
#define PPTP_WINDOW 3
#define PPTP_DELAY  0
#define PPTP_BPS_MIN 2400
#define PPTP_BPS_MAX 1000000000

#define PPTP_MAX_CHANNELS 65535
#define PPTP_FIRMWARE_VERSION 0x001
#define PPTP_HOSTNAME {'l','o','c','a','l',0}
#define PPTP_VENDOR   {'c','a','n','a','n','i','a','n',0}
#define PPTP_FRAME_CAP  PPTP_FRAME_ANY
#define PPTP_BEARER_CAP PPTP_BEARER_ANY

#endif /* INC_PPTP_OPTIONS_H */
