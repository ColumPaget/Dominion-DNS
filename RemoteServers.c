#include "RemoteServers.h"
#include "DNSMessage.h"
#include "Cache.h"
#include "Global.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


int RetryTimeout=5;
int FailThreshhold=5;
int QueryTimeout=30;
ModuleStruct *RemoteStats=NULL;

ListNode *RemoveQueryFromList(ListNode *Node)
{
QueryQueueItem *QueueItem;
DNSMessageStruct *DNSMsg;
ListNode *Prev;

Prev=ListGetPrev(Node);
QueueItem=(QueryQueueItem *)ListDeleteNode(Node); 
DNSMsg=QueueItem->QueryData;
DestroyDNSMessageStruct(DNSMsg);
ListDestroy(QueueItem->ServersForThisQuery, DestroyRR);

free(QueueItem); 
return(Prev);
}


/* This function sends queries to a number of DNS servers (more than 1 to */
/* optimise lookup times by asking multiple servers and going with first  */
/* response. Also this obviously gives a certain amount of robustness if  */
/* any of the remote servers stop responding */
void SendQueryToServers(ConnectStruct *UdpCon, QueryQueueItem *Query)
{
int ServerNo;
int pos;
int count, AvailServers;
DomainEntryStruct *ServerEntry=NULL;
int NoOfQueries;
ListNode *Curr;
ResourceRecord *RR;
ConnectStruct *Con;

if (! Query->CurrServer) return;
AvailServers=ListSize(Query->ServersForThisQuery);
if (Settings.MultiQuery > AvailServers) NoOfQueries=AvailServers;
else NoOfQueries=Settings.MultiQuery;


Curr=Query->CurrServer;
count=0;
while (Curr && (count < NoOfQueries))
{
	RR=(ResourceRecord *) Curr->Item;
	if (RR->Pref==USE_TCP)
	{
		Con=TCPFindQueryConnection(RR->Answer);
		if (! Con) Con=TCPConnectToServer(RR->Answer);
	}
	else Con=UdpCon;

	//if (Con && (Con->State > CON_INIT) && RR && (Query->QueryData->ClientIP != StrtoIP(RR->Answer))) 
	if (Con && (Con->State > CON_INIT) && RR) 
	{
		LogToFile(Settings.LogFilePath,"SENDQUERY: Ask %s about %s\n",RR->Answer,Query->QueryData->Question);
		SendQuery(Con, RR->Answer,Query->QueryData);
	}

	Curr=ListGetNext(Curr);
	count++;
}


Query->NoOfServersQueried=AvailServers;
Query->LastQueryTime=Now;


//   if (G_NoServersScript) Spawn(G_NoServersScript);

}



int ProcessQuery(QueryQueueItem *Query)
{
int len;
int result, ServerNo;
ListNode *Curr;
DomainEntryStruct *Server;
static int LinkFailure;


  if ((Now - Query->QueryStartTime) > QueryTimeout) 
  { 
      return(-1);
  }

       if ((Now - Query->LastQueryTime) < RetryTimeout) return(0);

       if (G_DialupLinkName)  
       {

          result=IsLinkUp();
result=1;
          //   if (result==-1)
          if (0)
          {
              /* if -1 then the link has timed out but not come up!! We launch the script  */
              /* to deal with this emergency (this is user defined in the ini file, and may*/
              /* for instance be a script that sends a mail to your network administrator  */
              /* saying 'AWOOOGA AWWWOOOOGA all hands to battle stations this is not a drill*/

              /* The LinkFailure variable ensures that we only run the failure script*/
              /* once (so that we don't send loads of mail or whatever)              */
              if (! LinkFailure)
              {
                  LinkFailure=1;
                 if (G_LinkTimeoutScript) Spawn(G_LinkTimeoutScript,"","","");
              }

              return(-1); /*This deletes the current queued query, as without a link we */
                          /* cannot satisfy it !                                        */
          }

          /* if result is zero then we are still waiting on the link to come up */
          if (result== 0)
          {
               /* We can't start timing out the query until we have timed out the link, or  */
               /* the link has come up. So we keep incrementing the LastQueryTime to prevent*/
               /* timeout and ensure that we start counting from when the link does come up */
               Query->LastQueryTime=Now; 
               return(0);
          }

      }



/* if link had failed previously then we do some things now that it has     */
/* recovered                                                                */

if (LinkFailure)
{
LinkFailure=0;
}

SendQueryToServers(Query->ServerCon, Query);

return(0);
}



int LookupNameServers(char *Domain, int QueryType, ListNode *RRList)
{
ResourceRecord *RR;
ListNode *Curr;
int count;
char *ptr;

/*
  if (QueryType==DNSREC_DOMAINNAME) RR=CreateRR(Domain,"0.0.0.0",0,0,AddressServer,CLASS_INTERNET);
  else */
ptr=Domain;
while (ptr)
{
	RR=CreateRR(ptr,"0.0.0.0",0,0,DNSREC_NAMESERVER,CLASS_INTERNET);
  CacheFindMatchRR(RR,CI_NS,RRList);
  DestroyRR(RR);

  count=0;
  Curr=ListGetNext(RRList);
  while (Curr)
  {
     count++;
     RR=(ResourceRecord *) Curr->Item;
     Curr=ListGetNext(Curr);
  }

if (count > 0) break;

ptr=strchr(ptr,'.');
if (ptr) ptr++;
}

return(count);
}


int FindNameServersForQuery(char *Question, int Type, ListNode *RRList)
{
int result;

result=LookupNameServers(Question, Type, RRList);
if (! result) result=LookupNameServers("0.0.0.0", Type, RRList);

return(result);
}



int QueryRemoteNameServer(ConnectStruct *Con, ConnectStruct *RemoteServersCon, DNSMessageStruct *Query)
{
ListNode *Curr, *RRList;
QueryQueueItem *QueueItem;
DNSMessageStruct *QueuedQuery;
ResourceRecord *RR;
int result;

/* Check that this Query is suitable for sending onto a remote server. */
/* Questions about the local domains are not forwarded. */

if (Query->Type==DNSREC_DOMAINNAME)
{
  if (! (Settings.Flags & FLAG_REF_AUTH)) return(FALSE);
}
else
{
  if (     
       (IsLocalDomainName(Query->Question))  ||
       (
         ((Settings.Flags & FLAG_SHORTNAMES_LOCAL) && 
         (strcmp(ExtractDomainName(Query->Question),"") ==0) )
       )
     )
     {
     return(FALSE);
     }
}


/* if the host in question has already got a query in the list then we don't*/
/* want to add another!                                                     */
Curr=ListGetNext(QueryListHead);
while(Curr)
{
   QueueItem=(QueryQueueItem *) Curr->Item;
   QueuedQuery=QueueItem->QueryData;
   if ( 
	(QueuedQuery->ClientIP==Query->ClientIP) &&
	(strcmp(QueuedQuery->Question,Query->Question)==0) &&
	(QueuedQuery->Type==Query->Type)
      ) 
   {
      return(TRUE);
   }
   Curr=ListGetNext(Curr);
}


/* We need to put it into the query into the query list so that we know what */
/* to do with the response when it comes back!                               */
QueuedQuery=(DNSMessageStruct *) CreateDNSMessageStruct();
CopyDNSMessageStruct(QueuedQuery, Query);


QueueItem=(QueryQueueItem *) calloc(1,sizeof(QueryQueueItem));
QueueItem->QueryData=QueuedQuery;
QueueItem->ClientCon=Con;
QueueItem->ServerCon=RemoteServersCon;

RRList=ListCreate();
result=FindNameServersForQuery(Query->Question, Query->Type, RRList);
QueueItem->ServersForThisQuery=RRList;
QueueItem->CurrServer=ListGetNext(RRList);


/* the next two lines are cheats to get the 'ProcessQuery' function to do a  */
/* query on this packet for the first nameserver (nameserver 0)              */
QueueItem->LastQueryTime=0;
QueueItem->QueryStartTime=Now;
ListAddItem(QueryListHead,(void *) QueueItem);
if (! RemoteStats) 
{
    RemoteStats=(ModuleStruct *) calloc(1,sizeof(ModuleStruct));
    RemoteStats->Name=CopyStr(RemoteStats->Name,"Remote");
}

RemoteStats->Lookups++;

/* Now start the query up in the query process (i.e. do the first actual     */
/* remote query).                                                            */
ProcessQuery(QueueItem);
return(TRUE);
}


void HandleServerConnected(ConnectStruct *ServerCon)
{
ListNode *Curr, *CurrServer;
QueryQueueItem *QueueItem;
ResourceRecord *RR;

Curr=ListGetNext(QueryListHead);
while (Curr)
{
  QueueItem=(QueryQueueItem *) Curr->Item;

  CurrServer=ListGetNext(QueueItem->ServersForThisQuery);
  while (CurrServer)
  {
	RR=(ResourceRecord *) CurrServer->Item;
	if ((strcmp(ServerCon->PeerName,RR->Answer)==0) && (QueueItem->QueryData->ClientIP != StrtoIP(RR->Answer))) 
  	{
     	SendQuery(ServerCon, RR->Answer,QueueItem->QueryData);
  	}
  CurrServer=ListGetNext(CurrServer);
  }

Curr=ListGetNext(Curr);
}

}


void ReprocessQueryList()
{
ListNode *Curr;
int result;
QueryQueueItem *QueueItem;
DNSMessageStruct *QueryData;

Curr=ListGetNext(QueryListHead);
while(Curr)
{

QueueItem=(QueryQueueItem *) Curr->Item;
QueryData=(DNSMessageStruct *) QueueItem->QueryData;

result=ProcessQuery(QueueItem);

if (result==-1) /*this means that we have tried all nameservers and not got */
{               /*an answer, hence give up and delete the query             */

  LogToFile(Settings.LogFilePath,"%s (%s) queried %s, NOT FOUND!",QueryData->ClientName, IPtoStr(QueryData->ClientIP),QueryData->Question);
  SendNotFoundResponse(QueueItem->ClientCon,QueryData);
  Curr=RemoveQueryFromList(Curr);
}

Curr=ListGetNext(Curr);
}

}


int CheckAddressList(char *Address, ListNode *List)
{
ListNode *Curr;

Curr=ListGetNext(List);
while (Curr)
{
if (strcmp(Curr->Item,Address)==0) return(TRUE);
Curr=ListGetNext(Curr);
}
return(FALSE);
}



int IsTrustedServer(DNSMessageStruct *Response, const char *ClientIP)
{
ListNode *RRList, *Curr;
ResourceRecord *RR;

RRList=ListCreate();
if (FindNameServersForQuery(Response->Question, Response->Type, RRList))
{
	Curr=ListGetNext(RRList);
	while (Curr)
	{
	RR=(ResourceRecord *) Curr->Item;
	if (strcmp(RR->Answer,ClientIP)==0) 
	{
		ListDestroy(RRList,DestroyString);
		return(TRUE);
	}
	Curr=ListGetNext(Curr);
	}
}

ListDestroy(RRList,DestroyString);
return(FALSE);
}



void HandleServerResponse(ConnectStruct *ServerCon, DNSMessageStruct *Response)
{
ListNode *Curr;
QueryQueueItem *CurrItem;
DNSMessageStruct *QueryData;
int FoundQuery=FALSE;
time_t LookupTime;
ResourceRecord *RR;
char *ClientIP=NULL;


if (! Response) return;
if (! Response->Question) return;

ClientIP=CopyStr(ClientIP,IPtoStr(Response->ClientIP));

if (! IsTrustedServer(Response, ClientIP))
{
	LogToFile(Settings.LogFilePath,"ALERT: Response from untrusted server [%s]. Possible attempt at DNS poisoning",ClientIP);
	DestroyString(ClientIP);
	return;
}

LogToFile(Settings.LogFilePath,"ANSWERS FROM: %s",ClientIP);
Curr=ListGetNext(Response->Answers);
while (Curr)
{
	RR=(ResourceRecord *) Curr->Item;

	LogToFile(Settings.LogFilePath,"   ANS: %s %s %d",RR->Question,RR->Answer,RR->TTL);
	Curr=ListGetNext(Curr);
}

/* the first item in the list is a blank 'head' node that we don't want to */
/* touch, so we get the next, which is the first valid entry in the list   */
Curr=ListGetNext(QueryListHead);

while (Curr !=NULL) 
{
    CurrItem=(QueryQueueItem *) Curr->Item;
    QueryData=CurrItem->QueryData;

if (  
	QueryData &&
	(strcmp(QueryData->Question,Response->Question)==0) 
   )
	{

  if (
              (Response->Header.ResponseCode==0) ||
              (Response->Header.ResponseCode==3)
      )
		{
			if (Response->Header.AuthAns || (Response->NoOfAnswers > 0))
			{
				QueryData->Header.AuthAns=Response->Header.AuthAns;
				QueryData->NoOfQuestions=1;
				if (Response->NoOfAnswers) QueryData->NoOfAnswers=Response->NoOfAnswers; 
				if (Response->NoOfNameservers) QueryData->NoOfNameservers=Response->NoOfNameservers; 
				QueryData->NoOfOtherRecords=0;
				
				LookupTime=Now - CurrItem->QueryStartTime;
				if (LookupTime > RemoteStats->LongestLookup) RemoteStats->LongestLookup=LookupTime;
				RemoteStats->Hits++;
				
				QueryData->AnswersSourceList=CatStr(QueryData->AnswersSourceList,"Remote ");
				
				QueryData->Answers=Response->Answers;
				QueryData->Nameservers=Response->Nameservers;
				LogToFile(Settings.LogFilePath,"%s (%s) queried %s, found in %s",QueryData->ClientName, ClientIP,QueryData->Question, QueryData->AnswersSourceList);
				SendResponse(CurrItem->ClientCon,QueryData); 
				QueryData->Answers=NULL;
				QueryData->Nameservers=NULL;
				
				Curr=RemoveQueryFromList(Curr);
				FoundQuery=TRUE;
			}
		}
		else
		{
			CurrItem->NoOfServersQueried--;
			CurrItem->CurrServer=ListGetNext(CurrItem->CurrServer);

			if (CurrItem->CurrServer !=NULL)
			{
				ProcessQuery(CurrItem);
			}

			if (CurrItem->NoOfServersQueried < 1) 
			{
				LogToFile(Settings.LogFilePath,"%s (%s) queried %s, NOT FOUND!",QueryData->ClientName,ClientIP, QueryData->Question);
				SendNotFoundResponse(CurrItem->ClientCon,QueryData);
				Curr=RemoveQueryFromList(Curr);
			}
		}
	}

Curr=ListGetNext(Curr);
}



/* A response code of zero means a successful answer, so we add it to the */
/* cache, any non-zero response is a problem                              */

if (Response->Header.ResponseCode==0)
{
	if (FoundQuery || (CheckAddressList(ClientIP, TrustedCacheUpdateSourceList)) )
	{
		if ((Settings.Flags & FLAG_USE_CACHE) && (Response->Type !=SOA)) 
		{
      //Response->Header.AuthAns=0;
      CacheAddDNSMessage(Response, 0); 
		}
	}
}


DestroyString(ClientIP);
}

