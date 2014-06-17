#include "DNSMessage.h"
#include "RemoteServers.h"
#include "Global.h"
#include "URL.h"
#include "ConfigFile.h"
#include "Modules.h"
#include "Manage.h"
#include "Cache.h"
#include "HandleQuery.h"

#include <sys/mount.h>
#include <pwd.h>

#define QTYPE_QUERY     1
#define QTYPE_RESPONSE  2
#define QTYPE_UPDATE    3

char *Version="1.0";

void FatalError(char *Fmt, ...)
{
va_list args;
char *Tempstr=NULL;

va_start(args,Fmt);
Tempstr=VFormatStr(Tempstr,Fmt, args);
va_end(args);
LogToFile(Settings.LogFilePath,"%s",Tempstr);
DestroyString(Tempstr);
exit(1);
}


void SigHUPHandler(int signum)
{
if (Settings.LogLevel) LogToFile(Settings.LogFilePath,"************* SIGHUP Received ***********");
LogFileFlushAll(LOGFILE_FLUSH);
}

void SigSegHandler(int signum)
{
if (Settings.LogLevel) LogToFile(Settings.LogFilePath,"ERROR:-------- SEG FAULT!!!!! ************");
LogFileFlushAll(LOGFILE_FLUSH);
abort();
}

void SigKillHandler(int signum)
{
if (Settings.LogLevel) LogToFile(Settings.LogFilePath,"**************** KILLED ****************");
LogFileFlushAll(LOGFILE_FLUSH);
exit(0);
}


void ProcessBindMounts()
{
ListNode *Curr;
char *Tempstr=NULL;

Curr=ListGetNext(Settings.BindMounts);
while (Curr)
{
	if (Curr->Item)
	{
	if (* (char *) Curr->Item == '/') Tempstr=CopyStr(Tempstr,Curr->Item);
	else if (StrLen(Settings.ChRoot)) Tempstr=MCopyStr(Tempstr,Settings.ChRoot,"/",Curr->Item,NULL);
	else Tempstr=MCopyStr(Tempstr,"./",Curr->Item,NULL);
  Tempstr=SlashTerminateDirectoryPath(Tempstr);
  MakeDirPath(Tempstr,0555);

  //Try a remount first. This prevents us mounting over and over
  //on the same mount point
  if (mount(Curr->Tag,Tempstr,"",MS_BIND | MS_REMOUNT,"") !=0)
  {
    mount(Curr->Tag,Tempstr,"",MS_BIND,"");
  }
	}

	Curr=ListGetNext(Curr);
}

ListDestroy(Settings.BindMounts,DestroyString);
Settings.BindMounts=NULL;

DestroyString(Tempstr);
}



int SetupWorkingEnvironment()
{
char *Possibilities[]={"nobody","daemon","guest","wwwrun",NULL};
struct passwd *pass_struct=NULL;
int i;


//get user details before we chroot
if (StrLen(Settings.RunAsUser)) pass_struct=getpwnam(Settings.RunAsUser);
else
{
	for (i=0; Possibilities[i] !=NULL; i++) 
	{
		pass_struct=getpwnam(Possibilities[i]);
		if (pass_struct) break;
	}
}


ProcessBindMounts();


if (Settings.ChRoot) 
{
	mkdir(Settings.ChRoot,0700);
	chdir(Settings.ChRoot);
	if (pass_struct) chown(Settings.ChRoot,pass_struct->pw_uid,pass_struct->pw_gid);
	chroot(".");
}


if (pass_struct) 
{
	//switch group first, because we wouldn't be able to switch group after we've given up root
	setgid(pass_struct->pw_gid);

	setresuid(pass_struct->pw_uid, pass_struct->pw_uid, pass_struct->pw_uid);
}

//make 'LogDir' under chroot, or else some logging will fail
mkdir(Settings.LogDir,0700);
//if (StrLen(Settings.RunAsGroup)) SwitchGroup(Settings.RunAsGroup);
}



void DominionInit()
{
char *tempstr;

time(&Now);
DominionStartTime=Now;

Settings.LogDir=CopyStr(NULL,"/var/log/dominion/");
Settings.LogFilePath=CopyStr(NULL,Settings.LogDir);
Settings.LogFilePath=CatStr(Settings.LogFilePath,"dominion.log");
Settings.LogLevel=1;
G_DialupLinkName=CopyStr(NULL,"ppp");
G_ConfigFilePath=CopyStr(NULL,"/etc/dominion.conf");
G_DomFilePath=CopyStr(NULL,"/usr/share/domain/root.dom");
G_DialupLinkTimeout=60;
G_MaxCacheSize=10000;
G_LinkTimeoutScript=NULL;
G_NoServersScript=NULL;
QueryListHead=ListCreate();
AliasListHead=ListCreate();
ModuleSettings=ListCreate();
LookupSourceList=ListCreate();
TrustedCacheUpdateSourceList=ListCreate();
UpdatesSendList=ListCreate();

Settings.Flags |= FLAG_USE_CACHE;
Settings.Interface=INADDR_ANY;
Settings.Port=53;
Settings.ResolveOrderList=ListCreate();
Settings.ConnectionLog=NULL;
Settings.ConfigReadTime=0;
Settings.DefaultTTL=999;
Settings.ForceDefaultTTL=0;
Settings.ChRoot=NULL;
Settings.SigKeyList=ListCreate();
Settings.MaxLogSize=100 * 1024 * 1024;
Settings.MultiQuery=5;

LogFileSetValues("", 0, Settings.MaxLogSize, 10);
ListAddItem(Settings.ResolveOrderList,CopyStr(NULL,"Dhcp"));
ListAddItem(Settings.ResolveOrderList,CopyStr(NULL,"Wins"));
ListAddItem(Settings.ResolveOrderList,CopyStr(NULL,"hostsfile"));
ListAddItem(Settings.ResolveOrderList,CopyStr(NULL,"Cache"));
ListAddItem(Settings.ResolveOrderList,CopyStr(NULL,"Remote"));

CacheInit();

signal(SIGHUP,SigHUPHandler);
signal(SIGINT,SigKillHandler);
signal(SIGTERM,SigKillHandler);
signal(SIGPIPE,SIG_IGN);
//signal(SIGSEGV,SigSegHandler);
}



void PrintVersion()
{
	fprintf(stdout,"version: %s\n",Version);
	fprintf(stdout,"\nBuilt: %s %s\n",__DATE__,__TIME__);
	fprintf(stdout,"libUseful: Version %s BuildTime: %s\n",LibUsefulGetValue("LibUsefulVersion"), LibUsefulGetValue("LibUsefulBuildTime"));
//	if (SSLAvailable()) fprintf(stdout,"SSL Library: %s\n",LibUsefulGetValue("SSL-Library"));
//	else fprintf(stdout,"%s\n","SSL Library: None, not compiled with --enable-ssl");

	exit(1);
}



/* Does exactly what it says, hopefully*/
void ParseCommandLine(int argc, char *argv[])
{
int count, command;
char *CommandLineStrings[]={"-nodemon","-c","-configfile","-l","-loglevel","-logfile","-i","-interface", "-port","-slave","-r","-chroot","-version","--version",NULL};
typedef enum {CL_NODEMON, CL_CONFIGSHORT, CL_CONFIG, CL_LOGLEVELSHORT,
CL_LOGLEVEL,CL_LOGFILE,CL_INTERFACESHORT, CL_INTERFACE, CL_PORT,CL_SLAVE,
CL_CHROOT_SHORT, CL_CHROOT_LONG,
CL_VERSION1, CL_VERSION2} Commands;


for (count=1; count <argc; count++)
{

  for (command=0; CommandLineStrings[command] !=NULL; command++)
  {
    if (strcmp(argv[count],CommandLineStrings[command])==0) break;
  }


 switch (command)
 {
   case CL_NODEMON:
		Settings.Flags |= FLAG_NODEMON;
   break;


   case CL_CONFIG:
   case CL_CONFIGSHORT:
   if (argc > count+1) 
   {
      G_ConfigFilePath=CopyStr(G_ConfigFilePath,argv[count+1]);
      ReloadConfigFile();
      count++;
   }
   break;
    
   case CL_LOGLEVELSHORT:
   case CL_LOGLEVEL:
   {
     if (argc > count+1)
     {
       Settings.LogLevel=atoi(argv[count+1]);
       count++;
     }
   }
  break;

  case CL_LOGFILE:
  if (argc > count+1)
  {
   Settings.LogFilePath=argv[count+1];
   count++;
  }
  break;

  case CL_INTERFACE:
  case CL_INTERFACESHORT:
  if (argc > count+1)
  {
    Settings.Interface=StrtoIP(argv[++count]);
  }
  break;

  case CL_PORT:
  if (argc > count+1)
  {
    Settings.Port=atoi(argv[++count]);
  }
  break;

  case CL_SLAVE:
    Settings.Flags |= FLAG_SLAVE_MODE;
  break;

  case CL_CHROOT_SHORT:
  case CL_CHROOT_LONG:
    Settings.ChRoot=CopyStr(Settings.ChRoot, argv[++count]);
  break;

	case CL_VERSION1:
	case CL_VERSION2:
	PrintVersion();
	break;
  }

}
}



int BindSock(unsigned long Interface, int type, int port)
{
int result, val;
struct sockaddr_in addr, peer_addr;
int fd;

addr.sin_family=AF_INET;
addr.sin_addr.s_addr=Interface;
addr.sin_port=htons(port);

fd=socket(AF_INET, type,0);
if (fd < 0) return(-1);

result=bind(fd,(struct sockaddr *) &addr, sizeof(addr));
if (result<0) 
{
close(fd);
return(-1);
}

val=TRUE;
setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&val, sizeof(val));
return(fd);
}


void HouseKeepDataSources()
{
ListNode *Curr;
ModuleStruct *LS;

/*
Curr=ListGetNext(LookupSourceList);
while (Curr)
{
LS=(ModuleStruct *) Curr->Item;
if (
	(LS->ReloadTime) &&
       	((Now - LS->LastReload) > LS->ReloadTime) &&
	(LS->CacheLoad)
   ) 
{
	LS->CacheLoad(LS);
	LS->LastReload=Now;
}

Curr=ListGetNext(Curr);
}
*/

}


void OpenLookupSources()
{
ListNode *Curr;
ModuleStruct *Module;

Curr=ListGetNext(LookupSourceList);
while (Curr)
{
	Module=(ModuleStruct *) Curr->Item;
	if (Module->Open) Module->Open(Module);
	Curr=ListGetNext(Curr);
}

}




main(int argc, char *argv[])
{
int count;
unsigned int salen;
short int QueryType;
int result;
ListNode *Curr, *Next;
ResourceRecord *RR;
unsigned long TTL;
struct timeval SockTimeout;
fd_set ReadSet, WriteSet;
int SlaveSyncInterval=100;
int LastSync;
time_t LastConfigReadTime=0;
char *tempstr=NULL;
int TCPServerSockFD=-1;
int HighFD;
ConnectStruct RemoteCon, LocalCon;


memset(&Settings,0,sizeof(Settings));
InitManage();

/************           INITIALIZATION HAPPENS FIRST            *************/

/*Parse command line args */
ParseCommandLine(argc,argv);


DominionInit();
ReloadConfigFile();
LogFileSetValues("", 0, Settings.MaxLogSize, 10);

/* make sure that the log directory exists */
mkdir(Settings.LogDir,0711);

/* re-read so that command line args over-ride any config file settings */
ParseCommandLine(argc,argv);

if (Settings.LogLevel) LogToFile(Settings.LogFilePath,"******* DOMINION STARTING UP *******");
if (! (Settings.Flags & FLAG_NODEMON)) demonize();


LocalCon.fd=BindSock(Settings.Interface, SOCK_DGRAM, Settings.Port);
LocalCon.State=CON_CONNECTED;
LocalCon.PeerName=CopyStr(NULL,"ResponseConnection");
if (LocalCon.fd==-1) FatalError("ERROR: Unable to bind to upd port %d... exiting",Settings.Port);
LocalCon.Buffer=SetStrLen(NULL,UDP_MSG_LEN);
LocalCon.Type=UDP_CONNECT;



RemoteCon.fd=BindSock(Settings.Interface, SOCK_DGRAM, 0);
RemoteCon.State=CON_CONNECTED;
RemoteCon.PeerName=CopyStr(NULL,"QueryConnection");
if (RemoteCon.fd==-1) FatalError("ERROR: Unable to open Outgoing Query Socket ... exiting");
RemoteCon.Buffer=SetStrLen(NULL,UDP_MSG_LEN);
RemoteCon.Type=UDP_CONNECT;


//if (0)
{
	TCPServerSockFD=BindSock(Settings.Interface, SOCK_STREAM, Settings.Port);
	//if (TCPServerSockFD==-1) FatalError("ERROR: Unable to bind to tcp port %d... exiting",Settings.Port);
	listen(TCPServerSockFD,10);
}

WritePidFile("dominion");
//do this to get stuff loaded into cache etc at startup
HouseKeepDataSources();


SetupWorkingEnvironment();
//if we chrooted in 'SwitchUserGroupAndDir', then we now open caches
//so any disk files are in the chroot
OpenLookupSources();
CacheOpenAll();

while(1)
{

/* We wait for a period of time to see if there is any data to read, if not */
/* then we do some house keeping and then loop round again                  */
SockTimeout.tv_usec=1;
SockTimeout.tv_sec=5;

FD_ZERO(&ReadSet);
FD_ZERO(&WriteSet);
HighFD=TCPAddSocksToSelect(&ReadSet,&WriteSet);
FD_SET(LocalCon.fd,&ReadSet);
if (LocalCon.fd > HighFD) HighFD=LocalCon.fd;
if (TCPServerSockFD > -1)
{
	FD_SET(TCPServerSockFD,&ReadSet);
	if (TCPServerSockFD > HighFD) HighFD=TCPServerSockFD;
}

FD_SET(RemoteCon.fd,&ReadSet);
if (RemoteCon.fd > HighFD) HighFD=RemoteCon.fd;

count=select(HighFD+1,&ReadSet,&WriteSet,NULL,&SockTimeout);

time(&Now);

HouseKeepDataSources();
ReprocessQueryList(&Settings);
/* to collect zombies */
waitpid(-1,&result,WNOHANG);

if (count <1) 
{
/*periodically re-read the config file. If ConfigReadTime has been set to zero*/
/*then this is disabled */
  if ( (Settings.ConfigReadTime) && ((Now - LastConfigReadTime)
                                             > Settings.ConfigReadTime) )
  {
      ReloadConfigFile();
      LastConfigReadTime=Now;
/*
      Curr=ListGetNext(UpdateListHead);
      if (Curr && (!Settings.Slave)) SyncHostsFileWithSlaveServers(ServerSockFD,(DomainEntryStruct *) Curr->Item);
*/
  }
continue;
}


salen=sizeof(struct sockaddr_in);
if (FD_ISSET(LocalCon.fd,&ReadSet))
{
  LocalCon.BytesRead=recvfrom(LocalCon.fd, LocalCon.Buffer,UDP_MSG_LEN,0, (struct sockaddr *)& LocalCon.sa, &salen);
  HandleIncomingDNSMessage(&LocalCon,&RemoteCon,&Settings);
}

if (TCPServerSockFD > -1)
{
	if (FD_ISSET(TCPServerSockFD,&ReadSet)) TCPAcceptConnection(TCPServerSockFD);
}

if (FD_ISSET(RemoteCon.fd,&ReadSet)) 
{
  RemoteCon.BytesRead=recvfrom(RemoteCon.fd,RemoteCon.Buffer,UDP_MSG_LEN,0, (struct sockaddr *) & RemoteCon.sa,&salen);
  HandleIncomingDNSMessage(&RemoteCon,&RemoteCon,&Settings);
}

TCPCheckConnections(&ReadSet, &Settings, &RemoteCon);
TCPCheckConnections(&WriteSet, &Settings, &RemoteCon);
TCPCloseIdleConnections();
LogFileFlushAll(0);
}


}
