#include "DNSMessage.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include "Global.h"


int SendQuery(ConnectStruct *Con, char *Server, DNSMessageStruct *Query)
{
struct sockaddr_in Send_sa;
int len, sendlen;
int salen, result;
char *Buffer=NULL;
int BuffLen=1024;

Buffer=SetStrLen(Buffer,BuffLen);
len=CreateQuestionPacket(Buffer,Buffer+BuffLen,Query->Question,Query->Type);
Con->LastActivity=Now;

if (len==0)
{
  LogToFile(Settings.LogFilePath,"ERROR: Zero length query packet");
  return(-1);
}


if (Settings.LogLevel >=LOG_REMOTE) LogToFile(Settings.LogFilePath,"REMOTE: Querying server %s for %s",Server,Query->Question);
if (Con->Type==TCP_CONNECT)
{
   sendlen=htons(len);
   result=write(Con->fd, &sendlen, sizeof(short int));
   if (result < 1) Con->State=CON_CLOSED;
   else 
   {
	result=write(Con->fd, Buffer, len);
   	if (result < 1) Con->State=CON_CLOSED;
   }
}
else
{
Send_sa.sin_family=AF_INET;
Send_sa.sin_addr.s_addr=StrtoIP(Server);
//Send_sa.sin_port=htons(Server->Port);
Send_sa.sin_port=htons(53);
salen=sizeof(struct sockaddr_in);
result=sendto(Con->fd,Buffer,len,0,(struct sockaddr *) &Send_sa,salen);
}

DestroyString(Buffer);
return(result);
}



void SendResponse(ConnectStruct *Con,DNSMessageStruct *Response)
{
struct sockaddr_in Send_sa;
short int sendlen;
int len, salen;
char *Buffer=NULL;
ListNode *Curr;
ResourceRecord *RR;

Buffer=SetStrLen(Buffer,1024);
len=CreateResponsePacket(Buffer,Buffer+1024,Response,&Settings);

if (len==0)
{
  LogToFile(Settings.LogFilePath,"ERROR: Zero length response packet");
	DestroyString(Buffer);
  return;
}

if (Con->Type==TCP_CONNECT)
{
   sendlen=htons(len);
   write(Con->fd, &sendlen, sizeof(short int));
   write(Con->fd, Buffer, len);
}
else if (Con->Type==UDP_CONNECT)
{
   Send_sa.sin_family=AF_INET;
   Send_sa.sin_addr.s_addr=Response->ClientIP;
   Send_sa.sin_port=Response->ClientPort;
   salen=sizeof(struct sockaddr_in);

   sendto(Con->fd,Buffer,len,0,(struct sockaddr *) &Send_sa,salen);
}
else LogToFile(Settings.LogFilePath,"ERROR: Unknown Comms Type %d on send",Con->Type);

if (Settings.LogLevel >= LOG_RESPONSES) 
{
	LogToFile(Settings.LogFilePath,"Sent %d answers to %s for %s query",ListSize(Response->Answers), IPtoStr(Response->ClientIP),Response->Question);

	Curr=ListGetNext(Response->Answers);
	while (Curr)
	{
		RR=(ResourceRecord *) Curr->Item;
		LogToFile(Settings.LogFilePath,"	ANS: %s->%s type=%d ttl=%d",RR->Question,RR->Answer,RR->Type,RR->TTL);
		Curr=ListGetNext(Curr);
	}
}

DestroyString(Buffer);
}



void SendNotFoundResponse(ConnectStruct *Con, DNSMessageStruct *Response)
{
  Response->NoOfAnswers=0;
  if (Response->Header.AuthAns) Response->Header.ResponseCode=3; /*3 is the code for 'name does not exist ' */
  SendResponse(Con,Response);
  if (Settings.LogLevel >= LOG_RESPONSES) LogToFile(Settings.LogFilePath,"Sending Not Found to %s %d query",Response->Question,Response->Type);
}


