#include "DNSMessage.h"
#include "RemoteServers.h"
#include "Global.h"
#include "URL.h"
#include "ACL.h"
#include "ConfigFile.h"
#include "Modules.h"
#include "Manage.h"
#include "Cache.h"


#define QTYPE_QUERY     1
#define QTYPE_RESPONSE  2
#define QTYPE_UPDATE    3


int CheckForLocalQuery(DNSMessageStruct *Query)
{
char *Tempstr=NULL;
int result=FALSE;

 if ( 
       (Query->Type==DNSREC_DOMAINNAME) 
    ) 
    {
	  Tempstr=DecodeAddressEntry(Tempstr,Query->Question);
          result=IsLocalDomainAddress(StrtoIP(Tempstr));
    }
 else if ( 
       (IsLocalDomainName(Query->Question)) 
    )
    {
      result=TRUE;
    }


DestroyString(Tempstr);
return(result);  
}


int ConstructStatsResponse(DNSMessageStruct *Query)
{
char *Tempstr=NULL, *Buffer=NULL;
ListNode *Curr;
ModuleStruct *LS;
ResourceRecord *RR;
time_t Diff;
struct tm *TMS;


TMS=localtime(&Now);
Buffer=SetStrLen(Buffer,255);
strftime(Buffer,255,"%d/%m/%Y %H:%M:%S",TMS);
Tempstr=CopyStr(Tempstr,"Dominion Stats at ");
Tempstr=CatStr(Tempstr,Buffer);

RR=CreateRR(Query->Question,Tempstr,0,999,DNSREC_TEXT, CLASS_INTERNET);
ListAddItem(Query->Answers, RR);
Query->NoOfAnswers++;

TMS=localtime(&DominionStartTime);
Buffer=SetStrLen(Buffer,255);
strftime(Buffer,255,"%d/%m/%Y %H:%M:%S",TMS);
Tempstr=CopyStr(Tempstr,"Server Started at ");
Tempstr=CatStr(Tempstr,Buffer);
RR=CreateRR(Query->Question,Tempstr,0,999,DNSREC_TEXT, CLASS_INTERNET);
ListAddItem(Query->Answers, RR);
Query->NoOfAnswers++;

/*
Diff=Now-DominionStartTime;
TMS=localtime(&Diff);

Tempstr=CopyStr(Tempstr,"Up for: ");
TMS->tm_year-=70;
if (TMS->tm_year > 0) 
{
  //year is translated into 'since 1900' but time gives us seconds since 1970!
  Buffer=FormatStr(Buffer,"%d years ",TMS->tm_year);
  Tempstr=CatStr(Tempstr,Buffer);
}

if (TMS->tm_mon > 0)
{
  Buffer=FormatStr(Buffer,"%d mon ",TMS->tm_mon);
  Tempstr=CatStr(Tempstr,Buffer);
}

if (TMS->tm_yday > 0) 
{
  Buffer=FormatStr(Buffer,"%d days ",TMS->tm_yday);
  Tempstr=CatStr(Tempstr,Buffer);
}

if (TMS->tm_hour > 0) 
{
  Buffer=FormatStr(Buffer,"%d hours ",TMS->tm_hour);
  Tempstr=CatStr(Tempstr,Buffer);
}

if (TMS->tm_min > 0) 
{
  Buffer=FormatStr(Buffer,"%d mins ",TMS->tm_min);
  Tempstr=CatStr(Tempstr,Buffer);
}

Buffer=FormatStr(Buffer,"%d secs ",TMS->tm_sec);
Tempstr=CatStr(Tempstr,Buffer);



RR=CreateRR(Query->Question,Tempstr,0,999,DNSREC_TEXT, CLASS_INTERNET);
ListAddItem(Query->Answers, RR);
Query->NoOfAnswers++;

*/


Curr=ListGetNext(LookupSourceList);
while (Curr)
{
	LS=(ModuleStruct *) Curr->Item;
	Tempstr=FormatStr(Tempstr,"%- 15s Lookups: % 10d Finds: % 10d Shortest: % 10d Longest: % 10d",LS->Name,LS->Lookups,LS->Hits,LS->ShortestLookup,LS->LongestLookup);
	RR=CreateRR(Query->Question,Tempstr,0,999,DNSREC_TEXT, CLASS_INTERNET);
	ListAddItem(Query->Answers, RR);
	Query->NoOfAnswers++;
        Curr=ListGetNext(Curr);
}


LS=RemoteStats;
if (LS)
{
Tempstr=FormatStr(Tempstr,"%- 15s Lookups: % 10d Finds: % 10d Shortest: % 10d Longest: % 10d",LS->Name,LS->Lookups,LS->Hits,LS->ShortestLookup,LS->LongestLookup);
RR=CreateRR(Query->Question,Tempstr,0,999,DNSREC_TEXT, CLASS_INTERNET);
ListAddItem(Query->Answers, RR);
Query->NoOfAnswers++;
}

DestroyString(Tempstr);  
DestroyString(Buffer);  

return(TRUE);
}



int CheckForLocalInterfaceQuery(DNSMessageStruct *Query)
{
int result=FALSE;
ResourceRecord *RR;
char *Answer=NULL, *Tempstr=NULL;


if (
//	(Query->Type==DNSREC_TEXT) && 
	(strcmp(Query->Question,"stats@dominion.localhost")==0)
   ) result=ConstructStatsResponse(Query);
else if ( 
       ( 
         (Query->Type==DNSREC_ADDRESS) && 
         (strcmp("localhost",Query->Question)==0) 
       ) ||
       ( 
         (Query->Type==DNSREC_DOMAINNAME) &&
         (strcmp("1.0.0.127.in-addr.arpa",Query->Question)==0) 
       ) 
    )
    {
      if (Query->Type==DNSREC_ADDRESS) Answer="127.0.0.1";
      else Answer="localhost";

      Query->NoOfAnswers++;
      RR=CreateRR(Query->Question,Answer,0,999,Query->Type, CLASS_INTERNET);
      ListAddItem(Query->Answers,RR);
      result=TRUE;
    }

DestroyString(Tempstr);
return(result);
}




void RegisterLookupTime(ModuleStruct *LookupSource, clock_t start,clock_t end, int Found)
{
long diff;
ListNode *Curr;

/*
diff=(end-start) / (CLOCKS_PER_SEC / 100000);
if ((diff < LookupSource->ShortestLookup) || (LookupSource->ShortestLookup==0)) LookupSource->ShortestLookup=diff;
if (diff > LookupSource->LongestLookup) LookupSource->LongestLookup=diff;

if (ListSize(LookupSource->LookupTimes) > 20)
{
   Curr=ListGetNext(LookupSource->LookupTimes);
   if (Curr) ListDeleteNode(Curr);
}

ListAddItem(LookupSource->LookupTimes,diff);
*/
if (Found) LookupSource->Hits++;
LookupSource->Lookups++;
}



void FormatDNSREC_DOMAINNAMEAnswers(ListNode *Answers)
{
ListNode *Curr;
ResourceRecord *RR;
char *Tempstr=NULL;

Curr=ListGetNext(Answers);
while (Curr)
{
    RR=(ResourceRecord *) Curr->Item;
    if (RR->Type==DNSREC_DOMAINNAME)
    {
	Tempstr=DecodeAddressEntry(Tempstr,RR->Question);
	Tempstr=CatStr(Tempstr,".in-addr.arpa");
	RR->Question=CopyStr(RR->Question,Tempstr);
    }
Curr=ListGetNext(Curr);
}
DestroyString(Tempstr);
}

int QueryLocalSources(DNSMessageStruct *Query)
{
int result=FALSE, count=0;
ResourceRecord *RR;
int LookupType;
ListNode *Curr, *CurrModule;
ModuleStruct *LookupSource;
char *SearchName=NULL;
clock_t start, end;


/* if this host has a registered alias (this is the internal aliasing system */
/* not CNAMES) then this function returns that alias, else it returns the    */
/* name that was passed into it.*/
if (Query->Type==DNSREC_DOMAINNAME)
{
  SearchName=DecodeAddressEntry(SearchName,Query->Question);

}
//else SearchName=GetAlias(Query->Question);
else SearchName=CopyStr(SearchName,Query->Question);

Curr=ListGetNext(Settings.ResolveOrderList);

while(Curr)
{

  CurrModule=ListGetNext(LookupSourceList);
  while (CurrModule)
  {
    LookupSource=(ModuleStruct *) CurrModule->Item;
    if ((LookupSource->Name) && (strcasecmp(LookupSource->Name,Curr->Item)==0) )
     { 
	  	start=clock();
      result=LookupSource->Search(LookupSource,SearchName,Query);
	  	end=clock();
			RegisterLookupTime(LookupSource,start,end,result);

			Query->AnswersSourceList=CatStr(Query->AnswersSourceList,LookupSource->Name);
			Query->AnswersSourceList=CatStr(Query->AnswersSourceList," ");
     	break;
     }
    CurrModule=ListGetNext(CurrModule);
  }
  /* if we found it then we will have broken from the inner loop, but we*/
  /* need to do the same for the outer */
   if (result) break;
  Curr=ListGetNext(Curr);
}

//The cache records come back as addresses, rather than in
//Reverse quad format, so we must reformat them
if (Query->Type==DNSREC_DOMAINNAME) FormatDNSREC_DOMAINNAMEAnswers(Query->Answers);


DestroyString(SearchName);
return(result);
}


int FindMatchingRRInList(ResourceRecord *RR, ListNode *List)
{
ListNode *Curr;
ResourceRecord *FoundRR;

Curr=ListGetNext(List);
while (Curr)
{
	FoundRR=(ResourceRecord *) Curr->Item;
	if (IsIdenticalRR(FoundRR,RR)) return(FoundRR);
	Curr=ListGetNext(Curr);
}

return(NULL);
}

typedef enum {UPE_NOERROR, UPE_FORMERR, UPE_SERVFAIL, UPE_NXDOMAIN, UPE_NOTIMP, UPE_REFUSED, UPE_YXDOMAIN, UPE_YXRRSET, UPE_NXRRSET, UPE_NOTAUTH, UPE_NOTZONE } TUpdatePrereqErrors;

int CheckPrerequisites(ListNode *Prerequisites)
{
ListNode *Curr;
ResourceRecord *RR;
int PreReqResult=UPE_NOERROR;
int NoOfAns=0;
ListNode *Answers;

Answers=ListCreate();
Curr=ListGetNext(Prerequisites);
while (Curr)
{
   RR=(ResourceRecord *) Curr->Item;
   CacheFindMatchRR(RR,CI_DNSUPDATE,Answers);

   NoOfAns=ListSize(Answers);
   if (StrLen(RR->Answer)==0)
   {
	   //require SOMEthing when name and type matches
	if ((RR->Class==CLASS_ANY) && (NoOfAns==0))
	{
		if (RR->Type==RT_ANY) PreReqResult=UPE_NXDOMAIN;
		else PreReqResult=UPE_NXRRSET;
		if (Settings.LogLevel & LOG_UPDATES)
		{
		 LogToFile(Settings.LogFilePath,"Update prerequisite failed, %s does not exist",RR->Question);	
}
		if (Settings.SyslogLevel & LOG_UPDATES) syslog(LOG_INFO,"Update prerequisite failed, %s does not exist",RR->Question);
		break;
	}
	   //require NOthing when name and type matches
	if ((RR->Class==CLASS_NONE) && (NoOfAns!=0))
	{
   		if (RR->Type==RT_ANY) PreReqResult=UPE_YXDOMAIN;
		else return(UPE_YXRRSET);
		if (Settings.LogLevel & LOG_UPDATES) LogToFile(Settings.LogFilePath,"Update prerequisite failed, %s exists",RR->Question);
		if (Settings.SyslogLevel & LOG_UPDATES) syslog(LOG_INFO,"Update prerequisite failed, %s exists",RR->Question);
   		break;
	}
   }
   //require SOMETHING Where name, type and answer matches
   else if  (! FindMatchingRRInList(RR, Answers))
   {
	   PreReqResult=UPE_NXRRSET;
		if (Settings.LogLevel & LOG_UPDATES) LogToFile(Settings.LogFilePath,"Update prerequisite failed, %s %s does not exist",RR->Question, RR->Answer);
		if (Settings.SyslogLevel & LOG_UPDATES) syslog(LOG_INFO,"Update prerequisite failed, %s %s does not exist",RR->Question, RR->Answer);
	   break;
   }

Curr=ListGetNext(Curr);
}

ListDestroy(Answers,DestroyRR);

return(PreReqResult);
}


int HandleUpdate(ConnectStruct *Con, DNSMessageStruct *Query)
{
int result=0, count;
ListNode *Curr;
ResourceRecord *RR;
DNSMessageStruct Response;
DomainEntryStruct *Domain;
int UpdateResult=UPE_NOERROR;
char *Tempstr=NULL;

//if (Settings.LogLevel & LOG_UPDATES)
{
 LogToFile(Settings.LogFilePath,"Update from %s:%s for %s",Query->ClientName,inet_ntoa(Query->ClientIP),Query->Question);
   /*if we are doing 'machine logs' then write to a file named after the client */
   if (Settings.Flags & FLAG_CLIENTLOGS) 
   {
        Tempstr=MCopyStr(Tempstr,Settings.LogDir,"/",Query->ClientName,".log", NULL);
        if (Settings.Flags & FLAG_CLIENTLOGS) LogToFile(Tempstr,"Update from %s %s",Query->ClientName, Query->Question);
   }
}

Tempstr=FormatStr(Tempstr,"UPDATE from %s:%s for %s, %d items",Query->ClientName,inet_ntoa(Query->ClientIP),Query->Question,Query->NoOfUpdateItems);
result=CheckACL(Query->Question,Tempstr, PT_UPDATE, Query->TsigAuth);
Tempstr=DestroyString(Tempstr); //DONT USE AFTER THIS POINT!!!

if (result == DOMAIN_DENY) 
{
	if (Settings.LogLevel & LOG_UPDATES) LogToFile(Settings.LogFilePath,"Update Denied from %s:%s for %s!",Query->ClientName,inet_ntoa(Query->ClientIP),Query->Question);
	if (Settings.SyslogLevel & LOG_UPDATES) syslog(LOG_INFO,"Update Denied from %s:%s for %s!\n",Query->ClientName,inet_ntoa(Query->ClientIP),Query->Question);
}
else
{
	Domain=FindLocalDomainForName(Query->Question,TRUE);
	if ((! Domain) || (! (Domain->Flags & DOMAIN_AUTH)))
	{
  if (Domain) LogToFile(Settings.LogFilePath,"NOT_AUTH %d",Domain->Flags);
  else LogToFile(Settings.LogFilePath,"NOT_AUTH No domain found");
  UpdateResult=UPE_NOTAUTH;
	}

	if (UpdateResult==UPE_NOERROR) UpdateResult=CheckPrerequisites(Query->UpdatePrerequisites);
	if (UpdateResult==UPE_NOERROR)
	{
		Curr=ListGetNext(Query->UpdateItems);
		while (Curr)
		{
			RR=(ResourceRecord *) Curr->Item;

			if (RR->TTL==0)
			{
				//	   if (RR->Type==none) RR->Type=RT_ANY;
				if (StrLen(RR->Answer)==0) RR->Answer=CopyStr(RR->Answer,"*");
				CacheDeleteRR(RR,CI_DNSUPDATE);
			}
			else CacheAddRR(RR,CI_DNSUPDATE);
			Curr=ListGetNext(Curr);
		}
		LogToFile(Settings.LogFilePath,"UPDATED: Source=%s name=%s type=%d!",Query->ClientName,Query->Question,Query->Type);
	}
	else LogToFile(Settings.LogFilePath,"Update Failed for Source=%s name=%s type=%d!",Query->ClientName,Query->Question,Query->Type);


	memset(&Response,0,sizeof(DNSMessageStruct));
	Response.MessageID=Query->MessageID;
	Response.Header.OpCode=Query->Header.OpCode;
	Response.Header.ResponseCode=UpdateResult;
	Response.Question=CopyStr(Response.Question,Query->Question);
	Response.Type=Query->Type;
	Response.ClientIP=Query->ClientIP;
	Response.ClientPort=Query->ClientPort;
	SendResponse(Con,&Response);
	DestroyString(Response.Question);
}

DestroyString(Tempstr);

return(TRUE);
}


     




char *FormatAddressLookup(char *Buffer, int IP)
{
char *Tempstr=NULL, *ReversedAddr=NULL;

Tempstr=CopyStr(Tempstr,IPtoStr(IP));
ReversedAddr=DecodeAddressEntry(Buffer, Tempstr);
ReversedAddr=CatStr(ReversedAddr, ".in-addr.arpa");
DestroyString(Tempstr);
return(ReversedAddr);
}


int HandleQuery(ConnectStruct *Con, ConnectStruct *RemoteCon, DNSMessageStruct *Query)
{
int result, IsLocalQuery=FALSE;
char *Tempstr=NULL;

   /* if we are doing any logging at all then here we should log that this      */
   /* particular client has made this request                                   */

   /*if we are doing 'client logs' then write to a file named after the client */
   if (Settings.Flags & FLAG_CLIENTLOGS) 
   {
        Tempstr=MCopyStr(Tempstr,Settings.LogDir,"/",Query->ClientName,".log", NULL);
        if (Settings.Flags & FLAG_CLIENTLOGS) LogToFile(Tempstr,"Lookup request for %s",Query->Question);
	Tempstr=DestroyString(Tempstr);
   }


     if (Settings.LogLevel & LOG_QUERIES) LogToFile(Settings.LogFilePath,"%s (%s) is asking after %s",Query->ClientName,IPtoStr(Query->ClientIP),Query->Question);
     if (Settings.SyslogLevel & LOG_QUERIES) syslog(LOG_INFO,"%s (%s) is asking after %s",Query->ClientName,IPtoStr(Query->ClientIP),Query->Question);

     /******* CHECK FOR 'BLACKLISTED' CLIENTS THAT WE DON'T WANT TO TALK TO  *******/
     /* Does this client have permission to talk? */

     result=CheckACL(Query->Question,"",PT_CLIENT,Query->TsigAuth);
     /* If this is someone that we don't want to give DNS services to then Log */
     /* the fact and cycle round to get the next query */

     if (result==DOMAIN_DENY)
     {
       if (Settings.LogLevel & LOG_DENIALS) LogToFile(Settings.LogFilePath,"Ignored Request from Blacklisted client %s (%s)",Query->ClientName,IPtoStr(Query->ClientIP));
       if (Settings.SyslogLevel & LOG_DENIALS) syslog(LOG_INFO,"Ignored Request from Blacklisted client %s (%s)",Query->ClientName,IPtoStr(Query->ClientIP));
	return(0);
     }



/****** CHECK IF THE REQUEST IS FOR A DOMAIN THAT WE DON'T WANT TO LET  ******/
/******************              ANYONE ACCESS           *********************/
/* This functionality has uses ranging from keeping school kids out of porn   */
/* sites to blocking lookups on 'advert' sites to get rid of banner adds on   */
/* webpages you are viewing.                                                  */

Tempstr=FormatStr(Tempstr,"Query from %s:%s for %s",Query->ClientName,inet_ntoa(Query->ClientIP),Query->Question);
result=CheckACL(Query->Question,Tempstr, PT_URL, Query->TsigAuth);
DestroyString(Tempstr);

/* Log the fact that we 'blocked' this request, send a 'No Such Host/Domain' */
/* Response, and then continue on to the next query.                         */

if (result==DOMAIN_DENY)
{
if (Settings.LogLevel & LOG_DENIALS) LogToFile(Settings.LogFilePath,"Blocked Request from %s for %s",IPtoStr(Query->ClientIP), Query->Question);
if (Settings.SyslogLevel & LOG_DENIALS) syslog(LOG_INFO,"Blocked Request from %s for %s",IPtoStr(Query->ClientIP), Query->Question);
SendNotFoundResponse(Con,Query);
return(0);
}

if (Query->Type==DNSREC_IP6ADDRESS) 
{
	SendNotFoundResponse(Con,Query);
	return(0);
}

IsLocalQuery=CheckForLocalQuery(Query);
result=QueryLocalSources(Query);
/* if the query is for 127.0.0.1, or localhost.localdomain then we answer it */
if (! result) result=CheckForLocalInterfaceQuery(Query);

if (! result) 
{
/* Check if we have a local name lookup and we have said that we don't allow */
/* these to go to the remote machine */

if (! IsLocalQuery)
{
/*
  if (! 
        (
          (Query->Type==DNSREC_DOMAINNAME) &&  0
          (! Settings.AllowRemoteNameForAddrLookups)
        )
     )
*/
     {
        result=QueryRemoteNameServer(Con, RemoteCon,Query);
        if (result) result=PENDING;
     }
}


}

if (IsLocalQuery) 
{
   Query->Header.AuthAns=TRUE;
}


/* NB, result can == 'PENDING' if we have sent a query to a remote server*/
/* so we cannot say 'if/else' here as we have more than 2 possible values*/


if (result==TRUE) 
{
   LogToFile(Settings.LogFilePath,"%s (%s) queried %s, found in %s",Query->ClientName, IPtoStr(Query->ClientIP), Query->Question, Query->AnswersSourceList);
   SendResponse(Con,Query);
}

if (result==FALSE) 
{
   LogToFile(Settings.LogFilePath,"%s (%s) queried %s, NO ANSWERS!",Query->ClientName, IPtoStr(Query->ClientIP), Query->Question);
   SendNotFoundResponse(Con,Query);
}

return(result);
}



void LoadClientInfo(DNSMessageStruct *Query)
{
DNSMessageStruct *ClientIDQuery;
ResourceRecord *RR;
ListNode *Curr;

   /* First lets get a name rather than an IP for this client */
   ClientIDQuery=CreateDNSMessageStruct();
   ClientIDQuery->Question=FormatAddressLookup(ClientIDQuery->Question, Query->ClientIP);
   ClientIDQuery->Type=DNSREC_DOMAINNAME;
   ClientIDQuery->NoOfQuestions=1;
   QueryLocalSources(ClientIDQuery);

   if (ClientIDQuery->NoOfAnswers > 0)
   {
      Curr=ListGetNext(ClientIDQuery->Answers);
      RR=(ResourceRecord *) Curr->Item;
      Query->ClientName=CopyStr(Query->ClientName,RR->Answer);
   }
   if (StrLen(Query->ClientName) < 1) Query->ClientName=CopyStr(Query->ClientName,IPtoStr(Query->ClientIP));

   DestroyDNSMessageStruct(ClientIDQuery);
}



void HandleIncomingDNSMessage(ConnectStruct *Con, ConnectStruct *RemoteCon)
{
DNSMessageStruct *Query;
int result;


  if (Con->BytesRead < 10) return; 

  Query=CreateDNSMessageStruct();

  DecodeDNSPacket(Con->Buffer,Query,Con->Buffer + Con->BytesRead);
  Query->ClientIP=Con->sa.sin_addr.s_addr;
  Query->ClientPort=Con->sa.sin_port;
  LoadClientInfo(Query);

  if (Query->Header.OpCode==OPCODE_UPDATE)
  {
      if (Settings.LogLevel & LOG_UPDATES) LogToFile(Settings.LogFilePath,"UPDATE from %s (%s) for %s",Query->ClientName,IPtoStr(Query->ClientIP),Query->Question);
      if (Settings.SyslogLevel & LOG_UPDATES) syslog(LOG_INFO,"UPDATE from %s (%s) for %s",Query->ClientName,IPtoStr(Query->ClientIP),Query->Question);
	  result=HandleUpdate(Con,Query);
  }
  else if (Query->Header.QR_Flag)
  {
      /* If the 'query' is really a response then we handle it here */
		HandleServerResponse(Con,Query); 
		result=TRUE;
  }
  else
  {
	  result=HandleQuery(Con,RemoteCon,Query);
  }


  DestroyDNSMessageStruct(Query);
}
