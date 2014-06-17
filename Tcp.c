#include "Tcp.h"
#include "HandleQuery.h"
#include <errno.h>

static ListNode *ConnectionList=NULL;

void TCPDestroyConnection(ConnectStruct *Con)
{
close(Con->fd);
DestroyString(Con->PeerName);
free(Con);
}

void TCPDisconnect(ConnectStruct *Con)
{
ListNode *Curr;

Curr=ListGetNext(ConnectionList);
while (Curr)
{
if (((ConnectStruct *) Curr->Item) == Con)
{
ListDeleteNode(Curr);
TCPDestroyConnection(Con);
break;
}
Curr=ListGetNext(Curr);
}


}


void TCPAcceptConnection(int ServerSock)
{
int fd, salen;
struct sockaddr_in sa;
ConnectStruct *Con;

if (! ConnectionList) ConnectionList=ListCreate();

salen=sizeof(sa);
fd=accept(ServerSock,(struct sockaddr *)& sa,&salen);
if (fd== -1) return;

Con=(ConnectStruct *) calloc(1,sizeof(ConnectStruct));
Con->Type=TCP_CONNECT;
Con->State=CON_CONNECTED;
Con->Direction=SERVER;
Con->fd=fd;
Con->sa=sa;
Con->LastActivity=Now;
ListAddItem(ConnectionList,Con);
}

ConnectStruct *TCPConnectToServer(char *Nameserver)
{
int fd, salen;
struct sockaddr_in sa;
ConnectStruct *Con;

if (! ConnectionList) ConnectionList=ListCreate();

salen=sizeof(sa);

//fd=ConnectToHost(Nameserver,53,FLAG_NONBLOCK);
fd=ConnectToHost(Nameserver,53,TRUE);

if (fd== -1) return;

Con=calloc(1,sizeof(ConnectStruct));
Con->Type=TCP_CONNECT;
Con->Direction=CLIENT;
Con->State=CON_INIT;
Con->PeerName=CopyStr(Con->PeerName,Nameserver);
Con->fd=fd;
Con->sa=sa;
Con->LastActivity=Now;
ListAddItem(ConnectionList,Con);
return(Con);
}


int TCPAddSocksToSelect(fd_set *ReadSet, fd_set *WriteSet)
{
ListNode *Curr;
ConnectStruct *Con;
int HighFD=0;

if (! ConnectionList)
{
     return(-1);
}

Curr=ListGetNext(ConnectionList);
   while (Curr)
   {
     Con=(ConnectStruct *) Curr->Item;
     if (Con->State==CON_INIT)
     {
	 FD_SET(Con->fd, WriteSet);
	 if (Con->fd > HighFD) HighFD=Con->fd;
     }
     else if (Con->State==CON_CLOSED)
     {
	 Curr=ListGetPrev(Curr);
	 TCPDisconnect(Con);
     }
     else
     {
		 FD_SET(Con->fd, ReadSet);
		 if (Con->fd > HighFD) HighFD=Con->fd;
     }
     Curr=ListGetNext(Curr);
   }
 return(HighFD);
}


ConnectStruct *TCPFindQueryConnection(char *ServerName)
{
ListNode *Curr;
ConnectStruct *Con;
int HighFD=0;

if (! ConnectionList)
{
     return(NULL);
}

Curr=ListGetNext(ConnectionList);
   while (Curr)
   {
	Con=(ConnectStruct *) Curr->Item;
	if (StrLen(Con->PeerName) && (strcasecmp(Con->PeerName,ServerName)==0)) return(Con);
	Curr=ListGetNext(Curr);
   }
 return(NULL);
}



int TCPHandleRead(ConnectStruct *Con)
{
short int len=0;
int result;

if (Con->MsgLen==0) 
{
    result=read(Con->fd, &len, sizeof(len));

    if (result < 1) return(-1);
    Con->MsgLen=ntohs(len);
    Con->BytesRead=0;
    Con->Buffer=SetStrLen(Con->Buffer, Con->MsgLen);
}

result=read(Con->fd, Con->Buffer + Con->BytesRead, Con->MsgLen - Con->BytesRead);

if (result < 0) return(-1);
Con->BytesRead+=result;
Con->LastActivity=Now;
if (Con->BytesRead >= Con->MsgLen) return(1);
return(0);
}


void TCPCheckConnections(fd_set *SelectSet, SettingsStruct *Settings, ConnectStruct *RemoteCon)
{
ListNode *Curr, *Next;
ConnectStruct *Con;
int result;

Curr=ListGetNext(ConnectionList);
   while (Curr)
   {
     Con=(ConnectStruct *) Curr->Item;
     Next=ListGetNext(Curr);

     if (FD_ISSET(Con->fd, SelectSet))
     {
	if (Con->State==CON_INIT)
	{
		fcntl(Con->fd,F_SETFL,0);
		Con->State=CON_CONNECTED;
		HandleServerConnected(Con, Settings);

	}
	else
	{
           result=TCPHandleRead(Con);
           if (result==-1) 
           {
              //close(Con->fd);
		ListDeleteNode(Curr);
		TCPDestroyConnection(Con);
           }

        	if (result==1)  
		{
		HandleIncomingDNSMessage(Con, RemoteCon, Settings);
		Con->MsgLen=0;
		}
	}
     }
    Curr=Next;
   }

}

void TCPCloseIdleConnections()
{
ListNode *Curr, *Next;
ConnectStruct *Con;
int result;

   Curr=ListGetNext(ConnectionList);
   while (Curr)
   {
     Con=(ConnectStruct *) Curr->Item;
     Next=ListGetNext(Curr);

     if ((Con->State > CON_INIT) && (Now-Con->LastActivity) > 10) 
     {
	ListDeleteNode(Curr);
	TCPDestroyConnection(Con);
     }
    Curr=Next;
   }
}
