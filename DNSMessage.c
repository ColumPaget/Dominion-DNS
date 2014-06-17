#include "DNSMessage.h"
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include "URL.h"
#include <ctype.h>
#include "Global.h"
#include <stdint.h>

#define HOSTNAMELEN_MAX 255

/*Functions for reading bits of the message */
int ReadUINT8(char *Data, int *Val)
{
*Val=(* (uint8_t *) Data);
return(sizeof(uint8_t));
}


int ReadUINT16(char *Data, int *Val)
{
*Val=ntohs(* (uint16_t *) Data);
return(sizeof(uint16_t));
}

int ReadUINT32(char *Data, int *Val)
{
*Val=ntohl(* (uint32_t *) Data);
return(sizeof(uint32_t));
}


int ReadINT32(char *Data, int *Val)
{
*Val=ntohl(* (int32_t *) Data);
return(sizeof(int32_t));
}

int WriteUINT8(char *Data, int Val)
{
(* (uint8_t *) Data)=Val;
return(sizeof(uint8_t));
}


int WriteUINT16(char *Data, int Val)
{
(* (uint16_t *) Data)=htons(Val);
return(sizeof(uint16_t));
}

int WriteUINT32(char *Data, int Val)
{
(* (uint32_t *) Data)=htonl(Val);
return(sizeof(uint32_t));
}


void CopyRRList(ListNode *DstList, ListNode *SourceList)
{
ListNode *Curr,*Next;
ResourceRecord *RR;

Curr=ListGetNext(SourceList);
while (Curr !=NULL)
{
  RR=CreateRR("","",0,0,0,CLASS_INTERNET);
  CopyRR(RR,(ResourceRecord *) Curr->Item);
  Curr=ListGetNext(Curr);
}


}



void CopyDNSMessageStruct(DNSMessageStruct *New, DNSMessageStruct *Old)
{

memcpy(& New->Header,& Old->Header, sizeof(DNSHeader));
New->MessageID=Old->MessageID;
New->NoOfQuestions=Old->NoOfQuestions;
New->NoOfAnswers=Old->NoOfAnswers;
New->NoOfNameservers=Old->NoOfNameservers;
New->NoOfPrerequisites=Old->NoOfPrerequisites;
New->NoOfUpdateItems=Old->NoOfUpdateItems;
New->NoOfOtherRecords=Old->NoOfOtherRecords;
New->Type=Old->Type;


New->ClientIP=Old->ClientIP;
New->ClientPort=Old->ClientPort;


New->Question=CopyStr(New->Question,Old->Question);
New->ClientName=CopyStr(New->ClientName,Old->ClientName);

/*
New->Answers=ListCreate();
New->UpdatePrerequisites=ListCreate();
New->Nameservers=ListCreate();
New->UpdateItems=ListCreate();
*/

CopyRRList(New->Answers, Old->Answers);
CopyRRList(New->Nameservers, Old->Nameservers);
CopyRRList(New->UpdatePrerequisites, Old->UpdatePrerequisites);
CopyRRList(New->UpdateItems, Old->UpdateItems);
}


DNSMessageStruct *CreateDNSMessageStruct()
{
DNSMessageStruct *NewStruct;

NewStruct=(DNSMessageStruct *) calloc(1,sizeof(DNSMessageStruct));
NewStruct->Question=NULL;
NewStruct->ClientName=NULL;
NewStruct->Answers=ListCreate();
NewStruct->UpdatePrerequisites=ListCreate();
NewStruct->Nameservers=ListCreate();
NewStruct->UpdateItems=ListCreate();


return(NewStruct);
}


void DestroyDNSMessageStruct(DNSMessageStruct *DNSStruct)
{
if (! DNSStruct) return;
DestroyString(DNSStruct->Question);
DestroyString(DNSStruct->ClientName);
DestroyString(DNSStruct->AnswersSourceList);
if (DNSStruct->Answers) ListDestroy(DNSStruct->Answers, DestroyRR);
if (DNSStruct->Nameservers) ListDestroy(DNSStruct->Nameservers, DestroyRR);
if (DNSStruct->UpdatePrerequisites) ListDestroy(DNSStruct->UpdatePrerequisites, DestroyRR);
if (DNSStruct->UpdateItems) ListDestroy(DNSStruct->UpdateItems, DestroyRR);
if (DNSStruct->OtherRecords) ListDestroy(DNSStruct->OtherRecords, DestroyRR);
free(DNSStruct);
}



/* We need to use this function to delete the answers list of a query because*/
/* the items within this list contain pointers to data which must itself be  */
/* freed. (C++ has its advantages eh?) */
/*
void DeleteRRList(ListNode *ListHead)
{
ListNode *Curr,*Next;
ResourceRecord *RR;

Curr=ListGetNext(ListHead);
while (Curr !=NULL)
{
  Next=ListGetNext(Curr);
  RR=(ResourceRecord *) ListDeleteNode(Curr);
  if (RR) DestroyRR(RR);
  Curr=Next;
}

ListDestroy(ListHead,NULL);
}
*/



int WriteHeader(char *Buffer, char *BuffEnd, int ID,int NoOfQuestions,int NoOfAnswers,int NoOfNSRR,int NoOfAddRR,DNSHeader *flags)
{
uint16_t *ptr, tempint;

ptr=(uint16_t *)Buffer;
if ((ptr+(6 * sizeof(uint16_t))) > BuffEnd) return(0);

*ptr=htons(ID);
ptr++;
memcpy(ptr,flags,sizeof(short));
ptr++;
*ptr=htons(NoOfQuestions);
ptr++;
*ptr=htons(NoOfAnswers);
ptr++;
*ptr=htons(NoOfNSRR);
ptr++;
*ptr=htons(NoOfAddRR);
ptr++;
return((char *)ptr-Buffer);
}




void ExtractQuadsFromAddr(char *Entry,char quads[4][4])
{
int count,len,quad_count,pos;

len=StrLen(Entry);

for (count=0; count < 4; count++) strcpy(quads[count],"0");

quad_count=0;
count=0;
pos=0;

while ((quad_count <4) && (count < len))
{
  while((count < len) && (pos < 4) && (Entry[count] !='.'))
  {
     if (! isdigit(Entry[count])) 
	{
		count=len;
		break;
	}

     quads[quad_count][pos]=Entry[count];
     count++;
     pos++;
  }
quads[quad_count][pos]=0; /*null terminate quad */
count++; /* takes us beyond the '.' */
quad_count++; /* next quad */
pos=0; /* start at begining of quad */
}
}


char *DecodeAddressEntry(char *DecodedStr, char *AddressStr)
{
int count;
char quads[4][4];
char *Tempstr=NULL;

Tempstr=CopyStr(DecodedStr,"");
ExtractQuadsFromAddr(AddressStr, quads);

/* IP Quads are reversed in dns messages */
for (count=3;count>=0;count--)
{
	Tempstr=CatStr(Tempstr,quads[count]);
	if (count >0) Tempstr=CatStr(Tempstr,".");
}
return(Tempstr);
}


int CheckForPtrBytes(char *Pos)
{
uint32_t val, *ptr;

ptr=(uint32_t *) Pos;
val=ntohs(*ptr);
if (val >49152) 
{
	val=val -49152;
	return(val);
}
else return(0);
}


/* This function reads a string consisting of a starting length octet (byte) */
/* followed by the string itself */
int ReadString(char *Data,int offset, char *ReturnString, char *EndOfMessage)
{
uint8_t len;
char *ptr;

ptr=Data+offset;
len=* (uint8_t *) ptr;
ptr++;
if (ptr+len > EndOfMessage) return(0);
strncpy(ReturnString,ptr,len);
ReturnString[len]=0;
return(len+1); //+1 to include length byte
}




/* This function just converts a string of tokens into a 'dotted' */
/* string, be it a domain name or an IP address */
int ReadDNSString(char *NameData,int InitialOffset,int max_len,char *ReturnBuffer, char *EndOfMessage)
{
int count=0,len=0, offset=0, ptrflag=0;
char *src_ptr, *dest_ptr, *dest_end, *retptr;

if (max_len==0) return(0);
src_ptr=NameData+InitialOffset;
dest_ptr=ReturnBuffer;
dest_end=ReturnBuffer+max_len;

//read strings until we get a 'length==0' situation
while((*src_ptr !=0) && (src_ptr < EndOfMessage) )
{

offset=CheckForPtrBytes(src_ptr);

/*
its impossible to have and offset of zero, as this would imply that there
was a string stored in the header of the dns packet, hence if the above
function returns zero, then we know that we aren't dealing with a pointer
byte here
*/
/* if offset < 0 then thats serious trouble! */
if (offset <0) return(0);


/* offset > 0 means we've got a pointer to someplace else */
if (offset > 0)
{
	/* if the offset points beyond EndOfMessage thats bad news too! */
	if (NameData+offset > EndOfMessage) return(0);

	ReadDNSString(NameData,offset,dest_end-dest_ptr,dest_ptr,EndOfMessage);
	src_ptr+=2;
	ptrflag=1;
	break;
}
else   /* offset==0 so not a pointer */
{
  len=*src_ptr;
  src_ptr++;


	/*copy string to destination, doing 'tolower' as we go*/
  for(count=0;(count <len) && (src_ptr <= EndOfMessage) ;count++)
  {
    *dest_ptr=tolower(*src_ptr);
    dest_ptr++;
    src_ptr++;
  }

	/*if *src_ptr != 0 then it's the length of another part of a hostname.*/
   if (*src_ptr !=0 )
   {
     *dest_ptr='.';
     dest_ptr++;
   }
   else 
   {
     *dest_ptr=0;
   }
}
}


/* Note, we can't have a pointer more than once in one string */
if (!ptrflag)
  {
   if ( *src_ptr==0 )
   {
      src_ptr++;   /* to get past null terminator */
   }
   else
   {

/*
     offset=CheckForPtrBytes(src_ptr);
     if (offset)
     {
       src_ptr+=2;
     }
*/

   }


}




//calcualte how far we've moved in the recieved messsage. this might not be far
//because the use of pointers means we might have read a long string in only 2 bytes
//worth of data
len=src_ptr-(NameData+InitialOffset);
return(len);
}




int ReadSectionIntoList(char *data, int offset, int *NoOfItems, ListNode *List, char *EndOfMessage, DNSMessageStruct *ReturnStruct)
{
int count, len;
int Type;
char *charptr;
ListNode *Curr;
ResourceRecord *RR;

charptr=data+offset;
for (count=0; count < *NoOfItems; count++)
{
 len=parse_answer((char *)data, (char *) charptr-data, List,EndOfMessage, ReturnStruct);

/* No point in throwing the baby out with the bathwater, we may have a useable*/
/* packet by now, so we stop reading answers instead of returning 0 and       */
/* throwing out the packet altogether.                                        */

if (len <1) break;

charptr+=len;
}

*NoOfItems=0;
Curr=ListGetNext(List);
while(Curr !=NULL)
{
RR=(ResourceRecord *) Curr->Item;
(*NoOfItems)++;
Curr=ListGetNext(Curr);
}

return(charptr-(data+offset));
}





int DecodeDNSPacket(char *data, DNSMessageStruct *ReturnStruct, char *EndOfMessage)
{
char *charptr;
int len,count;
int tempint;
ListNode *Curr;
ResourceRecord *RR;
char *Buffer=NULL;
int offset=0;
int *Section1Count, *Section2Count;
ListNode *Section1List, *Section2List;

Buffer=calloc(1,1024);
/* Do a bounds check to see that the message isn't shorter than it should be */
if (EndOfMessage-data < 10) return(0);

offset+=ReadUINT16(data+offset,&ReturnStruct->MessageID);
memcpy(&ReturnStruct->Header,data+offset, sizeof(uint16_t));

if (ReturnStruct->Header.OpCode==OPCODE_UPDATE)
{
Section1Count=& ReturnStruct->NoOfPrerequisites;
Section2Count=& ReturnStruct->NoOfUpdateItems;
Section1List=ReturnStruct->UpdatePrerequisites;
Section2List=ReturnStruct->UpdateItems;
}
else
{
Section1Count=& ReturnStruct->NoOfAnswers;
Section2Count=& ReturnStruct->NoOfNameservers;
Section1List=ReturnStruct->Answers;
Section2List=ReturnStruct->Nameservers;
}

offset+=ReadUINT16(data+offset,&tempint); // this is throwaway .. its just for offset increment
offset+=ReadUINT16(data+offset,&ReturnStruct->NoOfQuestions);
offset+=ReadUINT16(data+offset,Section1Count);
offset+=ReadUINT16(data+offset,Section2Count);
offset+=ReadUINT16(data+offset,&ReturnStruct->NoOfOtherRecords);

for (count=0 ; count < ReturnStruct->NoOfQuestions; count++)
{

  len=parse_question((char *) data,offset,Buffer,&(ReturnStruct->Type), &ReturnStruct->Class,EndOfMessage);

  ReturnStruct->Question=CopyStr(ReturnStruct->Question,Buffer);

  /* again, if the message is short then we have a bad packet, give up*/
  if (len <1)
  {
    return(0);
  }
  offset+=len;
}

len=ReadSectionIntoList(data,offset, Section1Count, Section1List,EndOfMessage, ReturnStruct);

offset+=len;
len=ReadSectionIntoList(data,offset, Section2Count, Section2List,EndOfMessage, ReturnStruct);

offset+=len;
len=ReadSectionIntoList(data,offset, &(ReturnStruct->NoOfOtherRecords), ReturnStruct->OtherRecords, EndOfMessage, ReturnStruct);

free(Buffer);
return(1);
}



int parse_question(char *NameData, int offset, char *QString, int *QType, int *QClass, char *EndOfMessage)
{
return(ParseRRSection(NameData,offset,QString,QType,QClass, EndOfMessage));
}


int parse_answer(char *NameData, int InitialOffset, ListNode *AnswersList, char *EndOfMessage, DNSMessageStruct *ReturnStruct)
{
int len;
int offset,count;
char *Question=NULL;
char *Answer=NULL;
char *RDataBuff;
uint32_t Type,Class;
unsigned int TTL;
ResourceRecord *RR;
SOADataStruct *SoaData;
uint32_t *longptr;
uint16_t *shortptr;

offset=InitialOffset;
Question=SetStrLen(Question,1024);
Answer=SetStrLen(Answer,1024);

/* This may seem strange but the first part of the answer section is */
/* actually a copy of the question it answers                        */
memset(Question,0,1024);
len=parse_question(NameData,offset,Question,&Type,&Class,EndOfMessage);

/* if we ran out of message then return*/
if (len <1) 
{
return(0);
}
offset+=len;

/* Check that we have enough message left for all our various fields */
if ( (NameData+offset+6) > EndOfMessage) 
{
return(0);
}

/* now we have the TTL field */
offset+=ReadINT32(NameData+offset,&TTL);

/* now the data length field */
offset+=ReadUINT16(NameData+offset,&len);

/* Another bounds check on the length of the message */
if ((NameData+offset+len) > EndOfMessage) 
{
return(0);
}

memset(Answer,0,1024);


switch (Type)
{
case DNSREC_ADDRESS: 
   // this can happen in dynamic updates, 
   // where a record has no answer data
   if (len==0)
   {
	   RR=CreateRR(Question, "",0,TTL,DNSREC_ADDRESS,Class);
   }
   else
   {
	   longptr=(uint32_t *) (NameData+offset);
	   offset+=4; //that was a four byte address!

     RR=CreateRR(Question, IPtoStr(*longptr),0,TTL,DNSREC_ADDRESS,Class);
   }
ListAddItem(AnswersList,(void *) RR);
break;

case DNSREC_IP6ADDRESS: 
   // this can happen in dynamic updates, 
   // where a record has no answer data
   if (len==0)
   {
	   RR=CreateRR(Question, "",0,TTL,DNSREC_IP6ADDRESS,Class);
   }
   else
   {
		 Answer=SetStrLen(Answer,255);
		 inet_ntop(AF_INET6, NameData+offset, Answer, 255);
     RR=CreateRR(Question, Answer, 0,TTL,DNSREC_IP6ADDRESS,Class);
	   offset+=16; //that was a 128 bit 16 byte address!
   }
ListAddItem(AnswersList,(void *) RR);
break;



case DNSREC_MAILEXCHANGE:
shortptr=(uint16_t *) (NameData+offset);
offset+=2;
offset+=ReadDNSString(NameData,offset,len,Answer,EndOfMessage); 
RR=CreateRR(Question,Answer,*shortptr,TTL,Type,Class);
ListAddItem(AnswersList,(void *) RR);
break;

case DNSREC_HOSTINFO:
len=ReadString(NameData,offset,Answer,EndOfMessage); 
offset+=len;
RR=CreateRR(Question,Answer,0,TTL,Type,Class);
len=ReadString(NameData,offset,Answer,EndOfMessage); 
offset+=len;
RR->Ptr=CopyStr(NULL,Answer);
ListAddItem(AnswersList,(void *) RR);
break;


case DNSREC_TEXT:
LogToFile(Settings.LogFilePath,"TXT: %d %s %d",Type,Question,*((uint8_t *) NameData+offset));
len=ReadString(NameData,offset,Answer,EndOfMessage); 
offset+=len;
RR=CreateRR(Question,Answer,0,TTL,Type,Class);
ListAddItem(AnswersList,(void *) RR);
break;

case SOA:
offset+=ReadDNSString(NameData,offset,len,Answer,EndOfMessage); 
RR=CreateRR(Question,"",0,TTL,Type,Class);
SoaData=(SOADataStruct *) calloc(1,sizeof(SOADataStruct));
SoaData->AuthSource=CopyStr(NULL,Answer);
offset+=ReadDNSString(NameData,offset,len,Answer,EndOfMessage); 
SoaData->AdminEmail=CopyStr(NULL,Answer);

longptr=(uint32_t *) (NameData+offset);
SoaData->SerialNo=*longptr;
  offset+=4; 
longptr=(uint32_t *) (NameData+offset);
SoaData->Refresh=*longptr;
  offset+=4; 
longptr=(uint32_t *) (NameData+offset);
SoaData->Retry=*longptr;
  offset+=4; 
longptr=(uint32_t *) (NameData+offset);
SoaData->Expire=*longptr;
  offset+=4; 
longptr=(uint32_t *) (NameData+offset);
SoaData->Minimum=*longptr;
  offset+=4; 

RR->Ptr=SoaData;
ListAddItem(AnswersList,(void *) RR);
break;

case RT_TSIG:
offset+=HandleTSIG(NameData,InitialOffset,offset,Question, TTL,len, EndOfMessage, ReturnStruct);
break;

/*
case DNSREC_DOMAINNAME: 
case CNAME:
case DNSREC_NAMESERVER:
case AddressServer:
case DNSREC_MAILDEST:
case DNSREC_MAILFORW:
case DNSREC_MAILDOM:
case DNSREC_MAILRENAME:
case DNSREC_MAILINFO:
*/
default:
offset+=ReadDNSString(NameData,offset,len,Answer,EndOfMessage); 
RR=CreateRR(Question,Answer,0,TTL,Type,Class);
ListAddItem(AnswersList,(void *) RR);
break;


}


len=offset-InitialOffset;

DestroyString(Question);
DestroyString(Answer);
return(len);
}






int ParseRRSection(char *Data,int InitialOffset,char *ResponseBuffer, int *Type, int *Class, char *EndOfMessage)
{
int count=0,len=0;
int offset;
char *Buffer=NULL;
char *ptr;

Buffer=(char *) calloc(1,1024);
len=ReadDNSString(Data,InitialOffset,HOSTNAMELEN_MAX,Buffer,EndOfMessage);

ptr=Data+InitialOffset+len;

// bounds check 
if (ptr+4 > EndOfMessage)
{
   free(Buffer);
   return(0);
}

/*
just after the question string (ip address, hostname or whatever) we will
find a two byte 'type code'
*/

*Type=ntohs(*(uint16_t *)ptr);
ptr+=sizeof(uint16_t); 
*Class=ntohs(*(uint16_t *)ptr);
ptr+=sizeof(uint16_t); 

strcpy(ResponseBuffer,Buffer);

/* we have to get past the 'type' and the 'class' field */

free(Buffer);
len=ptr-(Data+InitialOffset);
return(len);
}


int WriteString(char *Buffer, char *BuffEnd, char *String)
{
int len;
char *ptr;

ptr=Buffer;
len=StrLen(String);
if ((Buffer+len+1) > BuffEnd) return(0);
*ptr=(char) len;
ptr++;
strncpy(ptr,String,len);
return(len+1);
}


int WriteName(char *Buffer,char *BuffEnd, char *Name)
{
char *lenbyteptr;
char *ptr;
int len, count, tokenlen;

len=StrLen(Name);
if (len==0) return(0);
if ((Buffer+len) > BuffEnd) return(0);
tokenlen=0;
ptr=Buffer+1;
lenbyteptr=Buffer;
for (count=0;count <len;count++)
{
tokenlen++;
if (Name[count] != '.')
{
*ptr=Name[count];
ptr++;
}
else
{
*lenbyteptr=tokenlen-1;  /*dont want to include the '.' in the count*/
tokenlen=0;
lenbyteptr=ptr;
ptr++;
}
}

/*do this once more to get the '.com' or whatever on the end*/
*lenbyteptr=tokenlen;  /*this time no terminating '.'!*/
/*add a null to the end so that we know we have finished!*/
*ptr=0;
ptr++;

return(ptr-Buffer);
}


int CreateNameEntry(char *Buffer,char *BuffEnd, char *Name,short int Type)
{
char *ptr;
short int QClass,QType;

ptr=Buffer+WriteName(Buffer,BuffEnd,Name);

/* now we add on the two byte typecode */
QType=htons(Type);
memcpy(ptr,&QType,sizeof(uint16_t));
ptr+=sizeof(uint16_t);
QClass=htons(1);
memcpy(ptr,&QClass,sizeof(uint16_t));
ptr+=sizeof(uint16_t);
return(ptr-Buffer);

}


int CalcRRecRequiredSpace(ResourceRecord *RR)
{
SOADataStruct *SoaData;
int len;

len=StrLen(RR->Question) +1 + 2 * sizeof(uint16_t);

len+=sizeof(uint32_t) + sizeof(uint16_t);

switch (RR->Type)
{
case DNSREC_HOSTINFO:
len+=StrLen(RR->Answer)+1;
len+=StrLen((char *)RR->Ptr)+1;
break;

case DNSREC_TEXT:
len+=StrLen((char *)RR->Answer)+1;
break;


case DNSREC_ADDRESS:
if (StrLen(RR->Answer) > 0) len+=sizeof(uint32_t);
break;

case DNSREC_IP6ADDRESS:
if (StrLen(RR->Answer) > 0) len+=16;
break;


case DNSREC_MAILEXCHANGE:
len+=sizeof(uint16_t);
len+=StrLen(RR->Answer)+1;
break;

case SOA:
SoaData=(SOADataStruct *) RR->Ptr;
if (SoaData)
{
len+=StrLen(SoaData->AuthSource)+1;
len+=StrLen(SoaData->AdminEmail)+1;
len+=5*sizeof(uint32_t);
}
break;


case DNSREC_MAILDEST:
case DNSREC_MAILFORW:
case DNSREC_MAILDOM:
case DNSREC_MAILRENAME:
case DNSREC_MAILINFO:
case CNAME:
case DNSREC_DOMAINNAME:
case DNSREC_NAMESERVER:
case AddressServer:
default:
len+=StrLen(RR->Answer)+1;
break;
}


return(len);
}


char *EncodeSRV(char *Buffer, char *BuffEnd, ResourceRecord *RR)
{
char *start, *end, *ptr;

ptr=Buffer;

//encode priority 
start=RR->Answer;
end=strchr(start,':');
*end=0;

*(uint16_t *) atoi(start);
ptr+=2;
start=end+1;

//encode weight
end=strchr(start,':');
*end=0;

*(uint16_t *) atoi(start);
ptr+=2;
start=end+1;

//encode port
end=strchr(start,':');
*end=0;

*(uint16_t *) atoi(start);
ptr+=2;
start=end+1;

//encode target
ptr+=WriteName(ptr,BuffEnd,start);

return(ptr);
}


int CreateAnswerEntry(char *Buffer,char *BuffEnd, ResourceRecord *RR,uint32_t TTL)
{
int len;
char *ptr,*ResponseFieldLenPtr, *workptr;
SOADataStruct *SoaData;

len=CalcRRecRequiredSpace(RR);
if (Buffer+len > BuffEnd) 
{
    return(0);
}


len=CreateNameEntry(Buffer,BuffEnd,RR->Question,RR->Type);

ptr=Buffer+len;
*(uint32_t *)ptr=htonl(TTL);
ptr+=sizeof(uint32_t);

ResponseFieldLenPtr=ptr;
ptr+=sizeof(uint16_t);


switch (RR->Type)
{

case DNSREC_HOSTINFO:
ptr+=WriteString(ptr,BuffEnd,(char *)RR->Answer);
ptr+=WriteString(ptr,BuffEnd,(char *)RR->Ptr);
*(uint16_t *)ResponseFieldLenPtr=htons(ptr-(ResponseFieldLenPtr+sizeof(uint16_t)));
break;

case DNSREC_TEXT:
ptr+=WriteString(ptr,BuffEnd,(char *)RR->Answer);
*(uint16_t *)ResponseFieldLenPtr=htons(ptr-(ResponseFieldLenPtr+sizeof(uint16_t)));
break;



case DNSREC_ADDRESS:
if (StrLen(RR->Answer) > 0)
{
*(uint16_t *)ResponseFieldLenPtr=htons(sizeof(uint32_t));
*((uint32_t *) ptr)=StrtoIP(RR->Answer);
ptr+=sizeof(uint32_t);
}
else *(uint16_t *)ResponseFieldLenPtr=htons(0);
break;


case DNSREC_IP6ADDRESS:
if (StrLen(RR->Answer) > 0)
{
*(uint16_t *)ResponseFieldLenPtr=htons(16);
inet_pton(AF_INET6, RR->Answer, (void *) ptr);
ptr+=16;
}
else *(uint16_t *)ResponseFieldLenPtr=htons(0);
break;



case DNSREC_MAILEXCHANGE:
*(uint16_t *) ptr=RR->Pref;
ptr+=2;
ptr+=WriteName(ptr,BuffEnd, (char *)RR->Answer);
*(uint16_t *)ResponseFieldLenPtr=htons(ptr-(ResponseFieldLenPtr+sizeof(uint16_t)));
break;

case SOA:
SoaData=(SOADataStruct *) RR->Ptr;
if (SoaData)
{
ptr+=WriteName(ptr,BuffEnd,SoaData->AuthSource);
ptr+=WriteName(ptr,BuffEnd,SoaData->AdminEmail);

*(uint32_t *) ptr=SoaData->SerialNo;
ptr+=4;
*(uint32_t *) ptr=SoaData->Refresh;
ptr+=4;
*(uint32_t *) ptr=SoaData->Retry;
ptr+=4;
*(uint32_t *) ptr=SoaData->Expire;
ptr+=4;
*(uint32_t *) ptr=SoaData->Minimum;
ptr+=4;

*(uint16_t *)ResponseFieldLenPtr=htons(ptr-(ResponseFieldLenPtr+sizeof(uint16_t)));
}

break;

case SRV:
ptr=EncodeSRV(ptr,BuffEnd,RR);
*(uint16_t *)ResponseFieldLenPtr=htons(ptr-(ResponseFieldLenPtr+sizeof(uint16_t)));
break;

/*
case DNSREC_MAILDEST:
case DNSREC_MAILFORW:
case DNSREC_MAILDOM:
case DNSREC_MAILRENAME:
case DNSREC_MAILINFO:
case CNAME:
case DNSREC_DOMAINNAME:
case DNSREC_NAMESERVER:
case AddressServer:
*/
default:
ptr+=WriteName(ptr,BuffEnd,(char *)RR->Answer);
*(uint16_t *)ResponseFieldLenPtr=htons(ptr-(ResponseFieldLenPtr+sizeof(uint16_t)));
break;


}
return(ptr-Buffer);


}





int CreateDNSPacket(char *Buffer, char *BuffEnd, DNSMessageStruct *ResponseData, SettingsStruct *Settings)
{
char *ptr;
int packet_length;
ListNode *Curr;
ResourceRecord *RR;
int count, result;
int TTL;
int Section1Count, Section2Count;


if (StrLen(ResponseData->Question) <1) return(0);

ptr=Buffer;
if (ResponseData->Header.OpCode==OPCODE_UPDATE)
{
 Section1Count=ResponseData->NoOfPrerequisites;
 Section2Count=ResponseData->NoOfUpdateItems;
}
else
{
 Section1Count=ResponseData->NoOfAnswers;
 if (Settings && (Settings->Flags & FLAG_REF_AUTH)) Section2Count=ResponseData->NoOfNameservers;
	else Section2Count=0;
}


ptr+=WriteHeader(Buffer,BuffEnd, ResponseData->MessageID,1,Section1Count,Section2Count,0,&(ResponseData->Header));

ptr+=CreateNameEntry(ptr,BuffEnd, ResponseData->Question,ResponseData->Type);
packet_length=ptr-Buffer;

if (ResponseData->Header.OpCode==OPCODE_UPDATE)
{
      	Curr=ListGetNext(ResponseData->UpdatePrerequisites); 
}
else Curr=ListGetNext(ResponseData->Answers);

while (Curr)
{
    RR=(ResourceRecord *) Curr->Item;

    if (Settings && (Settings->Flags & FLAG_FORCE_TTL)) TTL=Settings->DefaultTTL;
    else TTL=RR->TTL;

    ptr+=CreateAnswerEntry(ptr,BuffEnd,RR,TTL);
    Curr=ListGetNext(Curr);
}



if (ResponseData->Header.OpCode==OPCODE_UPDATE) Curr=ListGetNext(ResponseData->UpdateItems); 
else if (Settings && (Settings->Flags & FLAG_REF_AUTH)) Curr=ListGetNext(ResponseData->Nameservers);
else Curr=NULL;

while (Curr)
{

    RR=(ResourceRecord *) Curr->Item;
		if (Settings && (Settings->Flags & FLAG_FORCE_TTL)) TTL=Settings->DefaultTTL;
    else TTL=RR->TTL;

    ptr+=CreateAnswerEntry(ptr,BuffEnd,RR,TTL);
    Curr=ListGetNext(Curr);
}




packet_length=ptr -Buffer;
return(packet_length);
}


int CreateResponsePacket(char *Buffer, char *BuffEnd, DNSMessageStruct *ResponseData, SettingsStruct *Settings)
{
ResponseData->Header.QR_Flag=1;
ResponseData->Header.AllowRecurse=1;


return(CreateDNSPacket(Buffer, BuffEnd, ResponseData, Settings));
}




int CreateQuestionPacket(char *Buffer,char *BuffEnd, char *Name,short int Type)
{
char *ptr;
int ID;
DNSHeader flags;

if (StrLen(Name) < 1) return(0);
ID=getpid();
memset(&flags,0,sizeof(DNSHeader));
flags.WantRecurse=1;
flags.AllowRecurse=1;

ptr=Buffer;
ptr+=WriteHeader(Buffer,BuffEnd,ID,1,0,0,0,&flags);
ptr+=CreateNameEntry(ptr,BuffEnd,Name,Type);
return(ptr-Buffer);
}




