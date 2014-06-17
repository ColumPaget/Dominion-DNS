#include "DialupLink.h"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <time.h>
#include <unistd.h>
#include "Global.h"

int IsLinkUp()
{
static time_t TimeWaitStarted;
time_t Now;

if ( IsInterfaceUp(G_DialupLinkName)==1 )
{
TimeWaitStarted=0;

return(1);
}

time(&Now);

if (TimeWaitStarted ==0) 
{
TimeWaitStarted=Now;
}


if (Now-TimeWaitStarted > G_DialupLinkTimeout) 
{
return(-1);
}

return(0);


}




int IsInterfaceUp(char *IfName)
{
char *Tempstr=NULL;
int result=FALSE;

Tempstr=CopyStr(Tempstr,"/var/run/");
Tempstr=CatStr(Tempstr,IfName);
Tempstr=CatStr(Tempstr,".pid");

if (access(Tempstr,F_OK)==0) result=TRUE;
DestroyString(Tempstr);

return(result);
}
