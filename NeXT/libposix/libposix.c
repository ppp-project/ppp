/*  Yes, that's right:  of all the platforms supported by ppp, 
    only Mach OpenStep 4.x doesn't support POSIX.  Sheesh.

    Stranger still, the POSIX declatations are still in the 4.x header files,
    and the gcc -posix still defines _POSIX_SOURCE.  So... 
    we emulate (sometimes badly) the missing POSIX functions.  This
    is by no means a complete or general POSIX emulation.  Just enough 
    to get us by for ppp, so we don't have to pollute the rest of the 
    sources of every other (non-braindead) platform.  Much of the
    code was snarfed from NeXT's 4.0 ppp port, the rest inspired by
    "POSIX Programmers Guide" by Donald Lewine.
    
    Maybe if we complain NeXT will upgrade to BSD4.4 libs like the rest of
    the free world (and maybe pink elephants will fly out of my...  -KC)
 */

#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>

int sigemptyset(sigset_t *set)
{
	*set = 0;
	return 0;
}

int sigaddset(sigset_t *set, int signo)
{
	*set |= 1<<signo;
	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
	switch(how) {
	case SIG_BLOCK:
		*oset = sigblock(*set);
		break;
	case SIG_UNBLOCK:
		/* XXX How does one emulate this with ancient BSD? (KC) */
		break;
	case SIG_SETMASK:
		*oset = sigsetmask(*set);
		break;
	}
	return 0;
}

int sigsuspend(const sigset_t *sigmask)
{
	sigpause(*sigmask);
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
	struct sigvec vec, ovec;
	int st;

	vec.sv_handler = act->sa_handler;
	vec.sv_mask = act->sa_mask;
	vec.sv_flags = act->sa_flags;
	
	st = sigvec(sig, &vec, &ovec);

	if (oact) {
		oact->sa_handler = ovec.sv_handler;
		oact->sa_mask = ovec.sv_mask;
		oact->sa_flags = ovec.sv_flags;
	}

	return st;
}

int tcgetattr(int fildes, struct termios *tp)
{
	return ioctl(fildes, TIOCGETA, tp);
}

int tcsetattr(int fd, int opt, const struct termios *t)
{
	int st;

	switch(opt) {
 	case TCSANOW:
		st = ioctl(fd, TIOCSETA, t);
		break;
	case TCSADRAIN:
		st = ioctl(fd, TIOCSETAW, t);
		break;
	case TCSAFLUSH:
		st = ioctl(fd, TIOCSETAF, t);
		break;
	default:
		st = -1;
		errno = EINVAL;
		break;
	}
	return st;
}

/*  XXX we ignore duration (which is 0 in chat.c anyway).
 */
int tcsendbreak(int fildes, int duration)
{
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	if (ioctl(fildes, TIOCSBRK, 0) != -1)
	{
	    select(0, 0, 0, 0, &sleepytime);
	    (void) ioctl(fildes, TIOCCBRK, 0);
	}
}

/*  XXX This is the implementation of cfgetospeed from NeXT's ppp-5
    pppd/sys-NeXT.c.  I don't know whether returning c_ispeed instead
    of c_ospeed is deliberate or a type-o.
 */
speed_t cfgetospeed(const struct termios *t)
{
	return t->c_ispeed;
}

int cfsetospeed(struct termios *t, int speed)
{ 
	t->c_ospeed = speed; 
	return 0; 
}

speed_t cfgetispeed(const struct termios *t)
{
	return t->c_ispeed;
}

int cfsetispeed(struct termios *t, int speed)
{ 
	t->c_ispeed = speed; 
	return 0; 
}

int setsid(void)
{
    int fd;

    setpgrp(0, getpid());
    
    if ( (fd = open("/dev/tty", O_RDWR | O_NDELAY)) < 0)
	    return -1;
    ioctl(fd, TIOCNOTTY, NULL);
    close(fd);

    return 0;
}

int waitpid(pid_t pid, int *stat_loc, int options)
{
    if (pid == -1) 
	pid = 0;
    return wait4(pid, (union wait *) stat_loc, options, NULL);
}

