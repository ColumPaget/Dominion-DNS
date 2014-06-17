#include "DNSMessage.h"
#include "URL.h"
#include "TSIG.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define DELETE_ALL 2


int OpenSock(int *sockfd,int port)
{
int result;
struct sockaddr_in addr, peer_addr;

result=1;

addr.sin_family=AF_INET;
//addr.sin_addr.s_addr=G_Interface;
addr.sin_addr.s_addr=INADDR_ANY;
addr.sin_port=htons(port);

*sockfd=socket(AF_INET, SOCK_DGRAM,0);
result=bind(*sockfd,(struct sockaddr *) &addr, sizeof(addr));
if (result<0) return(0);
else return(1);
}



void SendMessage(int sockfd,DNSMessageStruct *Response, TSigKey *Key)
{
struct sockaddr_in Send_sa;
int len, salen;
char *Buffer=NULL;
FILE *OutFile;

Buffer=SetStrLen(Buffer,1024);
len=CreateDNSPacket(Buffer,Buffer+1024,Response,NULL);
if (Key) len+=TSIGSignMessage("hmac-md5.sig-alg.reg.int",Buffer,len,Key);
printf("msg len=%d\n",len);
Send_sa.sin_family=AF_INET;
Send_sa.sin_addr.s_addr=Response->ClientIP;
Send_sa.sin_port=Response->ClientPort;
salen=sizeof(struct sockaddr_in);

OutFile=fopen("/tmp/updater.out","w");
fwrite(Buffer,1,len,OutFile);
sendto(sockfd,Buffer,len,0,(struct sockaddr *) &Send_sa,salen);

DestroyString(Buffer);
}


void InitUnsolicitedResponseMessage(DNSMessageStruct *Msg, char *Domain, int Type)
{
Msg->NoOfQuestions=0;
Msg->NoOfAnswers=0;
Msg->NoOfNameservers=0;
Msg->Question=CopyStr(Msg->Question, Domain);
Msg->Type=Type;
}

void UnsolicitedResponseAddItem(DNSMessageStruct *Msg, char *Question, char *Answer, int Priority, int TTL, int Type)
{
ListAddItem(Msg->Answers,CreateRR(Question,Answer,Priority,TTL,Type, CLASS_INTERNET));
Msg->NoOfAnswers++;
}


void InitDynamicUpdateMessage(DNSMessageStruct *Msg, char *Domain, int Type)
{
Msg->Header.OpCode=OPCODE_UPDATE;
Msg->Header.QR_Flag=0;
Msg->NoOfZoneItems=0;
Msg->NoOfPrerequisites=0;
Msg->NoOfUpdateItems=0;
Msg->Question=CopyStr(Msg->Question, Domain);
Msg->Type=Type;
}

void DynamicUpdateAddItem(DNSMessageStruct *Msg, char *Question, char *Answer, int Priority, int TTL, int Type)
{
ListAddItem(Msg->UpdateItems,CreateRR(Question,Answer,Priority,TTL,Type, CLASS_INTERNET));
Msg->NoOfUpdateItems++;
}



TSigKey *LoadSigKey(char *Line)
{
 char *Token=NULL, *ptr;
 TSigKey *Key;

 Key=(TSigKey *) calloc(1,sizeof(TSigKey));
 ptr=GetToken(Line," ",&Token,0); 
 ptr=GetToken(ptr," ",& Key->KeyName,0);
 ptr=GetToken(ptr," ",&Token,0);
 Key->KeyValue=SetStrLen(Key->KeyValue,40);
 Key->KeyLength=from64tobits(Key->KeyValue,Token);

 printf("Loaded tsig key %s\n",Key->KeyName);
 DestroyString(Token);

return(Key);
}



main(int argc, char *argv[])
{
int Delete=FALSE;
int sockfd, i;
char *Question=NULL, *Answer=NULL, *Server="127.0.0.1";
int TTL=555, Type=DNSREC_ADDRESS;
DNSMessageStruct *Message;
TSigKey *Key=NULL;

//Key=LoadSigKey("hmac-md5-base64 dnskeys.test xNa7QcIH5SeUOatiu2Iw6g==");
OpenSock(&sockfd,0);

for (i=1; i < argc; i++)
{
  if (strcmp(argv[i],"-d")==0) Delete=TRUE;
  else if (strcmp(argv[i],"-D")==0) Delete=DELETE_ALL;
  else if (strcmp(argv[i],"-s")==0) Server=argv[++i];
  else if (strcmp(argv[i],"-t")==0) Type=ParseQueryType(argv[++i]);
  else if (StrLen(Question) < 1) Question=argv[i];
  else Answer=argv[i];
}

Message=CreateDNSMessageStruct();
Message->ClientIP=StrtoIP(Server);
Message->ClientPort=htons(53);
Message->Answers=ListCreate();
Message->Nameservers=ListCreate();

InitDynamicUpdateMessage(Message,Question,Type);
if (Delete==TRUE)
{
  DynamicUpdateAddItem(Message,Question,Answer,0,0,Type);
}
if (Delete==DELETE_ALL)
{
  DynamicUpdateAddItem(Message,Question,"",0,0,RT_ANY);
}

if (StrLen(Answer))
{
 DynamicUpdateAddItem(Message,Question,Answer,0,TTL,Type);
}


SendMessage(sockfd,Message,Key);
}

