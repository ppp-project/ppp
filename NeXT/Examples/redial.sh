#!/bin/csh
# Script for multiple redialing to bring up PPP connection.
# Written by Colin.Allen@tamu.edu
# I make no warranties about this script, but if you have suggestions
# for improving it please feel free to email them to me.

# Last modified 11-29-95

if ( -f /usr/local/ppp/etc/ppp0.pid ) then

# The ppp0.pid file should only exist with an active ppp connection
# in which case we don't want to try to dial out. Sometimes the file
# will need to be deleted manually if ppp was dropped abnormally.

        echo ERROR: PPP already running.
        set quit = y
else
        set quit = n
        set count = 0
        set limit = 500
	set script = pppup

endif

while ( $quit != y );

# Next we loop as long as we are not quitting.  Each circuit we check
# for a connection and if it's there we launch PopOver.
# Delete or add other programs as desired.

        if ( -f /usr/local/ppp/etc/ppp0.pid ) then
                set quit = y
                echo Connected after $count attempts.
                echo -n "Launching PopOver...Process id: "
                nohup /LocalApps/PopOver.app/PopOver &
                echo Done.

# If the connection is not there we ascertain whether the modem is
# still trying to get a connection by looking to see if "chat" appears
# in the output of ps.  It is bound to appear at least once because ps
# will find the grep process.  If it appears exactly once then any
# previous connection attempt has failed and we need to allow time
# for the modem to reset, then we are free to dial again.

# You may be able to optimize this script by adjusting the sleep values
# below.  My modem (a ZyXEL 1496E) takes about 8 seconds to reset after
# hanging up.

        else
                set chat =  `ps | grep -c chat`
                if ( $chat == 1 ) then
                        if ( $count != 0 ) then
                                echo "no connect"
                                sleep 8
                        endif
                        @ count++
                        if ( $count == $limit ) then
                                echo "Dial count over limit.  Aborting."
                                set quit = y
                        else
                                /usr/local/ppp/scripts/$script
                                echo -n "($count) Dialing..."
                                sleep 5
                                echo -n "trying to connect..."
                                sleep 5
                        endif
                else

# If chat is still working we just wait a bit and loop again.

                        echo -n "."
                        sleep 5
                endif
        endif
end

