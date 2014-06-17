#ifndef DOM_DIALUP_LINK_H
#define DOM_DIALUP_LINK_H

/* These functions are for use in an enviroment where there is a dialup link */
/* to another network on which we will find our foreign nameservers. We wait */
/* for a timeout period to see the appropriate pid files in /var/run/. We do */
/* this by calling a function 'IsLinkUp' which checks for both ppp and isdn  */
/* links and returns 0 if we are still waiting for the link to come up, 1 if */
/* the link has come up, and -1 if the link has been timed out. This idea has*/
/* been taken from Matthew Pratts 'dproxy' program, which does the same thing*/
/* Although no code has been taken from dproxy it was *extreemly* influential*/
/* in terms of ideas which have been taken into dominion.                    */

int IsLinkUp();
int IsInterfaceUp(char *);

#endif

