Many thanks to:
   shess@winternet.com (Scott Hess)  
   andrew_abernathy@wire.seanet.com (Andrew Abernathy)
   michal@ellpspace.math.ualberta.ca (Michal Jaegermann)

for contributing programs that can take the place
of the pppdown script.  I have included Scott Hess's 
(now modified) here.  If you would like to see the other program, please
mail Andrew.

======================================================================

From shess@winternet.com Mon Jan  9 02:45 EST 1995
Date: Mon, 9 Jan 95 01:45 CST
From: shess@winternet.com (Scott Hess)
Reply-To: shess@winternet.com (Scott Hess)
To: Steve Perkins <perkins@cps.msu.edu>
Subject: Bringing down ppp.

[munch]

In any case, having to run pppdown as root has been annoying,
because I don't like to run things as root more than necessary.
In other words, more than about once a week is too often :-).  So,
I wrote the following quick&dirty hack.  Basic operation is to read
the pppd pid from a file where it's stored and send a SIGINT to
that process.  Since there's not a shell script in sight, this
should be a reasonably safe program to make setuid root.  [I'll
have to think on what someone can do if they crack it or /etc/ppp
and can send SIGINT to just anyone.  Perhaps it should check to
see if the process is really a pppd?  Oh, well.]

howard:/tmp> ls -l /usr/local/ppp/bin/killppp 

-rwsr-sr-x  1 root        1464 Jan  7 12:41 /usr/local/ppp/bin/killppp*
howard:/tmp> cat /usr/local/ppp/src/killppp.c 

/*
 * Originally written by Scott Hess <shess@winternet.com>
 * and later modified by Michal Jaegermann  <michal@ellpspace.math.ualberta.ca>
 */

#include <libc.h>
#include <stdio.h>


#include <libc.h>
#include <stdio.h>

#define PIDF "/etc/ppp/ppp0.pid"

int
main( void)
{
    FILE *ff;
    int pid;

    
    if( NULL == (ff = fopen( PIDF, "r"))) {
        perror( "opening " PIDF
	"\nppp0 link does not seem to be active" );
        exit(1);
    }
    

    if( fscanf( ff, "%d", &pid)<1) {
        fprintf( stderr, "Cannot read pid from" PIDF "\n");
        exit(1);
    }
    

    fclose( ff);
    if( kill( pid, SIGINT)==-1) {
        perror( "killing pppd");
	fprintf( stderr, "removing stale" PIDF "file\n");
	if (0 != unlink( PIDF)) {
	    perror("cannot remove" PIDF);
	}
	exit(1);
    }
    return 0;
}

Later,
---
scott hess <shess@winternet.com> (WWW to "http://www.winternet.com/~shess/")
Home:   12901 Upton Avenue South, #326  Burnsville, MN 55337  (612) 895-1208
Office: 101 W. Burnsville Pkwy, Suite 108E, Burnsville, MN 55337    890-1332
<?If you haven't the time to design, where will you find the time to debug?>

