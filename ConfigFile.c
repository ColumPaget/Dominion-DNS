#include "ConfigFile.h"
#include <stdio.h>
#include <stdlib.h>
#include "Global.h"
#include "Alias.h"
#include <fcntl.h>
#include <limits.h>
#include "Modules.h"
#include "Cache.h"
#include "TSIG.h"
#include "ACL.h"

/* This is an array list of default places to look for the config file */
char *ConfigFileList[]={"/etc/dominion.conf",
                   "/usr/local/etc/dominion.conf",NULL};



char *ParseList[]={"nameserver","addressserver","logfile","LogDir","ClientLogs",
"cache","deny","allow","DenyUpdate","AllowUpdate","block","pass",
"localdomain","remotedomain","dialuptimeout","TrustedCacheUpdateSource",
"NoLinkScript","NoServersScript","UnknownHost",
"BlockRemoteNameLookups", "ConnectLogFile","ShortNamesAreLocal","alias",
"include", "interface","ResolveOrder","defaultTTL",
"ForceDefaultTTL","SendUpdatesTo","remote","HideNameservers",
"SigKey","Authority","CacheModule","LookupModule",
"logclient","logquery","syslogclient","syslogquery","log","syslog", "MaxLogSize",
"MapName","RunAsUser","RunAsGroup",
"ChRoot", "BindMount",
NULL};

typedef enum {CONF_NAMESERVER, CONF_ADDRESSSERVER, CONF_LOGFILE, CONF_LOGDIR, CONF_CLIENTLOGS, CONF_CACHE,
CONF_DENY, CONF_ALLOW, CONF_DENY_UPDATE, CONF_ALLOW_UPDATE, CONF_BLOCK, CONF_PASS, CONF_LOCAL_DOMAIN, 
CONF_REMOTE_DOMAIN, CONF_DIALTIME, CONF_TRUST_UP_SRC, 
CONF_NO_LINK_SCRIPT, CONF_NO_SERVERS_SCRIPT, CONF_REQ_FROM_UNKNOWN_SCRIPT,
CONF_BLOCK_REMOTE_NAME, CONF_CONNECT_LOG_FILE, CONF_SHORT_NAMES_LOCAL, 
CONF_ALIAS, CONF_INCLUDE, CONF_INTERFACE, 
CONF_RESOLVE_ORDER, CONF_DEF_TTL, CONF_FORCE_DEF_TTL, CONF_SEND_UPDATES_TO, 
CONF_REMOTE, CONF_HIDENAMESERVERS, CONF_SIGNKEY,CONF_AUTHORITY, 
CONF_CACHEMODULE, CONF_LOOKUPMODULE,
CONF_LOG_CLIENT, CONF_LOG_QUERY, CONF_SYSLOG_CLIENT, CONF_SYSLOG_QUERY, CONF_LOG, CONF_SYSLOG, CONF_MAXLOGSIZE,
CONF_MAPNAME, CONF_RUNASUSER, CONF_RUNASGROUP,
CONF_CHROOT, CONF_BINDMOUNT
} ConfigTokens;



int ReadBoolFromString(char *string)
{
if (! string) return(FALSE);
if ((toupper(string[0])=='Y') || (strcmp(string,"1")==0) || 
     (strcasecmp(string,"true")==0)) return(TRUE);
return(FALSE);
}



void ReadSigKey(ListNode *SigKeyList, char *Line)
{
 TSigKey *Key;
 char *Token=NULL, *ptr;

 Key=(TSigKey *) calloc(1,sizeof(TSigKey));
 ptr=GetToken(Line," ",&Token,0); 
 ptr=GetToken(ptr," ",& Key->KeyName,0);
 ptr=GetToken(ptr," ",&Token,0);
 Key->KeyValue=SetStrLen(Key->KeyValue,40);
 Key->KeyLength=from64tobits(Key->KeyValue,Token);

 ListAddItem(SigKeyList, Key);
 DestroyString(Token);
}


void ReadAuthority(char *Line)
{
char *ptr, *Domain=NULL, *NS=NULL, *Token=NULL;
ResourceRecord *RR;
SOADataStruct *SoaData;

ptr=GetToken(Line," ",&Domain,0);

RR=CreateRR(Domain,"",0,0,SOA,CLASS_INTERNET);

ptr=GetToken(ptr," ",&NS,0);
ptr=GetToken(ptr," ",&Token,0);
RR->Ptr=CreateSOAStruct(NS, Token, 0, 900, 300, 900, 400);

CacheAddRR(RR,0);

RR=CreateRR(Domain,NS,0,0,DNSREC_NAMESERVER,CLASS_INTERNET);
CacheAddRR(RR,0);
AddDomainItemToList(LocalDomainsListHead,Domain,"",DOMAIN_LOCAL| DOMAIN_AUTH);
}




ModuleStruct *ReadPluginModule(char *Line)
{
char *ptr, *Token=NULL, *Name=NULL, *Value=NULL;
ModuleStruct *Item;
char *TokenList[]={"name","type","path","reload","ttl","module",NULL};
typedef enum {LST_NAME,LST_TYPE,LST_PATH,LST_RELOAD,LST_TTL, LST_MODULE};
int result;

Item=CreateModuleStruct();
ptr=GetToken(Line," ",&Token,0);
while (ptr)
{
 Value=CopyStr(Value,GetToken(Token,"=",&Name,0));

 StripLeadingWhitespace(Value); 
 StripTrailingWhitespace(Value); 
 StripLeadingWhitespace(Name); 
 StripTrailingWhitespace(Name); 

 result=MatchTokenFromList(Name, TokenList,0);

  switch(result)
  {
	case LST_NAME:
	  Item->Name=CopyStr(Item->Name,Value);
	break;


	case LST_TYPE:
	break;

	case LST_PATH:
	  Item->Path=CopyStr(Item->Path,Value);
	break;

	case LST_RELOAD:
	  Item->ReloadTime=atoi(Value);
	break;

	case LST_TTL:
	  Item->DefaultTTL=atoi(Value);
	break;

	case LST_MODULE:
		Item->ModulePath=CopyStr(Item->ModulePath,Value);
	break;
  }

  ptr=GetToken(ptr," ",&Token,0);
}


if (Item->ModulePath) LoadModule(Item);

DestroyString(Name);
DestroyString(Value);
DestroyString(Token);

return(Item);
}


int ParseLogLevel(int Level, char *Data)
{
char *ptr1, *Token=NULL;
char *LevelStrings[]={"queries","updates","denials",NULL};
int result, ReturnVal;

   ReturnVal=Level;
   ptr1=GetToken(Data," ",&Token,0);
   while (ptr1)
   {
	result=MatchTokenFromList(Token,LevelStrings,0);
	if (result > -1)
	{
		ReturnVal |= result;
	}
   	ptr1=GetToken(ptr1," ",&Token,0);
   }
DestroyString(Token);
}

void ConfigFileParseNSAddress(char *Data,char **Address,int *PrefVal)
{
char *ptr, *Token=NULL;

if (! strchr(Data,':')) *Address=CopyStr(*Address,Data);
else
{
    ptr=GetToken(Data,":",&Token,0);
    ptr=GetToken(ptr,":",Address,0);
    if (StrLen(Token) && (strcasecmp(Token,"tcp")==0)) *PrefVal=USE_TCP;
    else if (StrLen(Token) && (strcasecmp(Token,"ssl")==0)) *PrefVal=USE_SSL;
}

DestroyString(Token);
}


void ConfigFileParseNameserverLine(char *Line)
{
char *Address=NULL, *Domain=NULL, *Token=NULL;
char *ptr;
int PrefVal=USE_UDP;
ResourceRecord *RR;

     ptr=GetToken(Line," ",&Token,0);
     do
     {
       if (ptr)
       {
		ptr=GetToken(ptr," ",&Domain,0);
       		StripTrailingWhitespace(Domain);
       }
       if (StrLen(Domain) <1)   Domain=CopyStr(Domain,"0.0.0.0");
          ConfigFileParseNSAddress(Token,&Address,&PrefVal);
	  if (StrLen(Domain) && StrLen(Address))
	  {
		printf("AddNS %s %s\n",Domain,Address);
             RR=CreateRR(Domain,Address,PrefVal,0,DNSREC_NAMESERVER,CLASS_INTERNET);
             CacheAddRR(RR,CI_NS);
	  }
     } while (StrLen(ptr));
     
DestroyString(Address);
DestroyString(Domain);
}

void ReadConfigFile(char *ConfigFilePath, SettingsStruct  *Settings)
{
STREAM *ConfigFile;
char *Line=NULL, *Token=NULL;
int count=0;
char *ptr1, *ptr2;
ListNode *Curr;
ResourceRecord *RR;
ModuleStruct *Module;

/* if no config file was specified on the command line then we check thru */
/* the array of likely places to look                                     */
if (! ConfigFilePath)
{
while ((ConfigFileList[count] !=NULL) && (ConfigFile==NULL))
{
ConfigFile=STREAMOpenFile(ConfigFileList[count],O_RDONLY);

if (Settings->LogLevel && (ConfigFile==NULL)) LogToFile(Settings->LogFilePath,"Config file = %s",ConfigFileList[count]);

count++;
}
}
else ConfigFile=STREAMOpenFile(ConfigFilePath,O_RDONLY);

if (ConfigFile !=NULL)
{

 Line=STREAMReadLine(Line,ConfigFile);
 while(Line)
 {
  StripLeadingWhitespace(Line);
  StripTrailingWhitespace(Line);
  ptr1=GetToken(Line,"\\S",&Token,0);
  count=MatchTokenFromList(Token,ParseList,0);

switch (count)
{
/* A line naming a foreign nameserver */
case CONF_NAMESERVER:
	ConfigFileParseNameserverLine(ptr1);
     break;

/* A line naming a foreign nameserver */
/*
case CONF_ADDRESSSERVER:
     ptr1=GetToken(ptr1," ",&Token,0);
     if (ptr1) ptr1=GetToken(ptr1," ",&Domain,0);
     if (StrLen(Domain) <1)  Domain=CopyStr(Domain,"0.0.0.0");
     RR=CreateRR(Domain,Token,0,0,AddressServer,CLASS_INTERNET);
     CacheAddRR(RR,CI_NS);
     break;
*/

/* a line telling us where to log data */
case CONF_LOGFILE:
   Settings->LogFilePath=CopyStr(Settings->LogFilePath,ptr1);
   break;

case CONF_LOGDIR:
   Settings->LogDir=CopyStr(Settings->LogDir,ptr1);
   break;

/* a line telling us to keep logs for each machine that connects */
case CONF_CLIENTLOGS:
     if (ReadBoolFromString(ptr1)) Settings->Flags |= FLAG_CLIENTLOGS;
     else Settings->Flags &= ~FLAG_CLIENTLOGS;
   break;

/* a line telling us to use the memory cache */
case CONF_CACHE:
   if (ReadBoolFromString(ptr1)) Settings->Flags |= FLAG_USE_CACHE;
	 else Settings->Flags &= ~FLAG_USE_CACHE;
   break;

/* a line telling us to deny use of this DNS server to an IP/hostname */
case CONF_DENY:
    RR=CreateRR(ptr1,"deny",0,0,PT_CLIENT,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;


/* a line telling us to allow domain lookups to an IP/hostname */
case CONF_ALLOW:
    RR=CreateRR(ptr1,"allow",0,0,PT_CLIENT,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;

case CONF_ALLOW_UPDATE:
    RR=CreateRR(ptr1,"allow",0,0,PT_UPDATE,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;

case CONF_DENY_UPDATE:
    RR=CreateRR(ptr1,"deny",0,0,PT_UPDATE,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;


/* a line identifying a domain that we wish to 'block' i.e. this server will*/
/* not answer requests for this domain, it will claim that it does not exist*/
case CONF_BLOCK:
     RR=CreateRR(ptr1,"deny",0,0,PT_URL,CLASS_INTERNET);
     CacheAddRR(RR,CI_ACL);
   break; 

/* a line identifying a domain that we wish to allow clients to do lookups for*/
/* (i.e. the opposite of 'block' above.                                       */
case CONF_PASS:
    RR=CreateRR(ptr1,"allow",0,0,PT_URL,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;

case CONF_LOG_CLIENT:
    RR=CreateRR(ptr1,"log",0,0,PT_CLIENT,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;

case CONF_SYSLOG_CLIENT:
    RR=CreateRR(ptr1,"syslog",0,0,PT_CLIENT,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
    openlog("dominion",LOG_PID,LOG_DAEMON);
   break;

case CONF_LOG_QUERY:
    RR=CreateRR(ptr1,"log",0,0,PT_URL,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
   break;

case CONF_SYSLOG_QUERY:
    RR=CreateRR(ptr1,"syslog",0,0,PT_URL,CLASS_INTERNET);
    CacheAddRR(RR,CI_ACL);
    openlog("dominion",LOG_PID,LOG_DAEMON);
   break;

case CONF_LOG:
   Settings->LogLevel=ParseLogLevel(Settings->LogLevel,ptr1);
   break;

case CONF_SYSLOG:
   Settings->SyslogLevel=ParseLogLevel(Settings->SyslogLevel,ptr1);
   break;

case CONF_MAXLOGSIZE:
   Settings->MaxLogSize=atoi(ptr1);
   break;



/* a line identifying a domain that we consider 'local' */
case CONF_LOCAL_DOMAIN:
   ptr2=strchr(ptr1,' ');
   if (ptr2)
   {
     *ptr2=0;
     ptr2++;
   }
   AddDomainItemToList(LocalDomainsListHead,ptr1,ptr2,DOMAIN_LOCAL);
   break;

/* a line identifying a domain that we consider 'remote' */
case CONF_REMOTE_DOMAIN:
   ptr2=strchr(ptr1,' ');
   if (ptr2)
   {
     *ptr2=0;
     ptr2++;
   }
 
   AddDomainItemToList(LocalDomainsListHead,ptr1,ptr2,DOMAIN_REMOTE);
   break;

case CONF_TRUST_UP_SRC:
	ListAddItem(TrustedCacheUpdateSourceList,ptr1);
   break;



/* The timeout for waiting for a dialup ppp or isdn link to come up */
case CONF_DIALTIME:
   G_DialupLinkTimeout=atoi(ptr1);
   break;

/*
case CONF_DOMAINFILE:
   G_DomFilePath=CopyStr(G_DomFilePath,ptr1);
break;
*/  


/* A line that specifies a script to run in the event of the dialup link    */
/* failing to come up.                                                      */
case CONF_NO_LINK_SCRIPT:
   G_LinkTimeoutScript=CopyStr(G_LinkTimeoutScript,ptr1);
   break;

/* A line that specifies a script to run in the event all the remote servers  */
/* being timed out                                                            */
case CONF_NO_SERVERS_SCRIPT:
   G_NoServersScript= CopyStr(G_NoServersScript,ptr1);
   break;

/* Do we allow 'name for address' (DNSREC_DOMAINNAME) lookups to go to the Remote*/
/* servers?                                                                  */
case CONF_BLOCK_REMOTE_NAME:
     if (ReadBoolFromString(ptr1)) Settings->Flags |= FLAG_BLOCK_REVERSE_LOOKUPS;
     else Settings->Flags &= ~FLAG_BLOCK_REVERSE_LOOKUPS;
   break;

/* Name of a connection log file so we can see who is bringing up a dialup  */
/* link.                                                                    */
case CONF_CONNECT_LOG_FILE:
   Settings->ConnectionLog=CopyStr(Settings->ConnectionLog,ptr1);
   break;

/* Name lookups lacing a domain extension (i.e of the form 'machine' rather   */
/* than 'machine.domain.tld' are treated as local and not allowed to do remote*/
/* Lookups                                           */
case CONF_SHORT_NAMES_LOCAL:
     if (ReadBoolFromString(ptr1)) Settings->Flags |= FLAG_SHORTNAMES_LOCAL;
     else Settings->Flags &= ~FLAG_SHORTNAMES_LOCAL;
   break;



case CONF_ALIAS:
   ptr2=strchr(ptr1,' ');
   if (ptr2)
   {
     *ptr2=0;
     ptr2++;
   }
   AddDomainItemToList(AliasListHead,ptr1,ptr2,0);
   break;


case CONF_MAPNAME:
    ptr1=GetToken(ptr1," ",&Token,0);
    RR=CreateRR(Token,ptr1,0,0,CNAME,CLASS_INTERNET);
    CacheAddRR(RR,CI_QUERY);
   break;


case CONF_INCLUDE:
  ReadConfigFile(ptr1,Settings);
  break; 

case CONF_INTERFACE:
  if ( (strcasecmp(ptr1,"ALL")==0) || (strcmp(ptr1,"0.0.0.0")==0) )
	Settings->Interface=INADDR_ANY;
  else Settings->Interface=StrtoIP(ptr1);  
  break;

case CONF_RESOLVE_ORDER:
/*read the rest of this line*/
while (ptr1)
{
ptr2=strchr(ptr1,' ');
if (ptr2)
{
*ptr2=0;
ptr2++;
}
ListAddItem(Settings->ResolveOrderList,CopyStr(NULL,ptr1));
ptr1=ptr2;
}
break;

case CONF_DEF_TTL:
Settings->DefaultTTL=atoi(ptr1);
break;

case CONF_FORCE_DEF_TTL:
     if (ReadBoolFromString(ptr1)) Settings->Flags |= FLAG_FORCE_TTL;
     else Settings->Flags &= ~FLAG_FORCE_TTL;
break;



/* A host that we should send updates to (i.e. a slave host that we send */
/* copies of our domain data to so that it is synchronized with us*/
case CONF_SEND_UPDATES_TO:
break;

case CONF_HIDENAMESERVERS:
     if (ReadBoolFromString(ptr1)) Settings->Flags &= ~FLAG_REF_AUTH;
     else Settings->Flags |= FLAG_REF_AUTH;
break;



case CONF_CHROOT:
     Settings->ChRoot=CopyStr(Settings->ChRoot,ptr1);
break;

case CONF_BINDMOUNT:
		if (! Settings->BindMounts) Settings->BindMounts=ListCreate();
  	ptr1=GetToken(ptr1,"\\S",&Token,0);
		SetVar(Settings->BindMounts,Token,ptr1);
break;

case CONF_SIGNKEY:
     ReadSigKey(Settings->SigKeyList,ptr1);
break;

case CONF_AUTHORITY:
		ReadAuthority(ptr1);
break;

case CONF_LOOKUPMODULE:
	Module=ReadPluginModule(ptr1);
	if (Module->Search) ListAddItem(LookupSourceList,Module);
break;

case CONF_CACHEMODULE:
	Module=ReadPluginModule(ptr1);
	//We defer opening caches, until after chroot
	if (Module) CacheLoadModule(Module,CI_QUERY);
break;


case CONF_RUNASUSER:
	Settings->RunAsUser=CopyStr(Settings->RunAsUser,ptr1);
break;

case CONF_RUNASGROUP:
	Settings->RunAsGroup=CopyStr(Settings->RunAsGroup,ptr1);
break;


default:
/* anything we don't recognize we presume is a setting for a module, as we */
/* want to be able to drop in new modules without altering other aspects of*/
/* the code then we load anything we don't deal with above into a general  */
/* settings list which is made available to the run-time loadable modules  */

SetVar(ModuleSettings,Token,ptr1);
break;

}


 Line=STREAMReadLine(Line,ConfigFile);
}

STREAMClose(ConfigFile);

}
else if (Settings->LogLevel) LogToFile(Settings->LogFilePath,"Cannot open Config File %s\n",ConfigFilePath);

DestroyString(Line);
DestroyString(Token);
}


void DestroyDomainsArray(DomainEntryStruct **Array)
{
int count=0;
DomainEntryStruct *ptr;

if (Array==NULL) return;

do
{
ptr=Array[count];
count++;
if (ptr) 
{
if (ptr->Name) free(ptr->Name);
free(ptr);
}
}
while(ptr !=NULL);
free(Array);

}


void AddDomainItemToList(ListNode *DomainList,char *Name,char *Address,int val)
{
DomainEntryStruct *DomainEntry;
char *ptr, *AddrStr, *NameStr;

   DomainEntry=(DomainEntryStruct *) calloc(1,sizeof(DomainEntryStruct));
   if (IsAddress(Name))
   {
    AddrStr=Name;
    NameStr="";
   }
   else 
   {
    AddrStr=Address;
    NameStr=Name;
   }


   ptr=strchr(AddrStr,':');
   if (ptr) 
   {
     *ptr=0;
     ptr++;
     DomainEntry->Port=atoi(ptr);
   }
   else DomainEntry->Port=53;

   DomainEntry->Address=StrtoIP(AddrStr);
   DomainEntry->Name=CopyStr(NULL,strlwr(NameStr));

   DomainEntry->Flags=val;
   
   ListAddItem(DomainList,DomainEntry);
}



/* Obviously this reloads the config file, to do this it must do more than */
/* just read it from disk, it must also destroy and rebuild some of the    */
/* data structures within the program */

void ReloadConfigFile()
{
 ListDestroy(ModuleSettings, DestroyString);
 ListDestroy(Settings.ResolveOrderList,DestroyString);

	LocalDomainsListHead=ListCreate();

	ModuleSettings=ListCreate();
	Settings.ResolveOrderList=ListCreate();

	ReadConfigFile(G_ConfigFilePath, &Settings);
}

