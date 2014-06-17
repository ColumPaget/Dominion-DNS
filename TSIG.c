#include <stdio.h>
#include <stdint.h>
#include "Global.h"
#include "TSIG.h"
#include "DNSMessage.h"

#define BLOCK_LEN 64
#define MD5LEN 16
#define IPAD 0x36
#define OPAD 0x5c


typedef struct
{
uint64_t Timestamp:48;
uint64_t Fudge:16;
} TSIG_TIME;




TSigKey *GetKey(char *KeyName)
{
ListNode *Curr;
TSigKey *Key;

Curr=ListGetNext(Settings.SigKeyList);
while (Curr)
{
  Key=(TSigKey *) Curr->Item;
  if (strcmp(Key->KeyName,KeyName)==0) return(Key);
  Curr=ListGetNext(Curr);
}
return(NULL);
}




void GenerateTSIGHash(char *Msg, int MsgLen, char *AlgName, TSigKey *Key, TSIG_TIME *TimeData, int Error, char **Digest, int *DigLen)
{
int len;
char *Buffer=NULL, *ptr;
THash *HMAC;

printf("ALG=%s\n",AlgName);
printf("KEY=%s\n",Key->KeyName);
len=MsgLen + 128 + StrLen(AlgName) + StrLen (Key->KeyName) +1024;
Buffer=CopyStr(Buffer,"");
Buffer=SetStrLen(Buffer, len);
ptr=Buffer;
memcpy(ptr,Msg,MsgLen);
ptr+=MsgLen;
ptr+=WriteName(ptr,Buffer+len,Key->KeyName);

//QCLASS field.. set to 'any' (255)
*((uint16_t *) ptr)=htons(255);
ptr+=sizeof(uint16_t);
//TTL.. set to zero
*((uint32_t *) ptr)=0; ptr+=sizeof(uint32_t);
//Algorithm name in canonical dns wire format
ptr+=WriteName(ptr,Buffer+len,AlgName);
memcpy(ptr,TimeData,8);
ptr+=8;


*((uint16_t *) ptr)=Error; ptr+=sizeof(uint16_t);
*((uint16_t *) ptr)=0; ptr+=sizeof(uint16_t);

if (! Key) printf("No key!\n");
else printf("Got TSIG %s %s %d\n",Key->KeyName,AlgName,ptr-Buffer);


HMAC=HashInit("hmac-md5");
HMACSetKey(HMAC, Key->KeyValue, Key->KeyLength);
HMAC->Update(HMAC, Buffer, ptr-Buffer);
*DigLen=HMAC->Finish(HMAC, ENCODE_HEX, Digest);
HashDestroy(HMAC);


//*DigLen=MD5LEN;

DestroyString(Buffer);
}





int HandleTSIG(char *NameData, int TsigOffset, int CurrOffset, char *KeyName, unsigned int TTL, int RDataLen, char *EndOfMessage, DNSMessageStruct *DNSMsg)
{
TSigKey *Key;
char *Buffer=NULL, *Digest=NULL, *AlgName=NULL, *SentDigest=NULL, *ptr;
int OrigID, Error, OtherData;
int count, offset, len;
int i;
time_t SignTime;
TSIG_TIME TimeData;

printf("KeyName %s\n",KeyName);

offset=CurrOffset;
offset+=ReadDNSString(NameData,offset,RDataLen,AlgName,EndOfMessage); 
memcpy(&TimeData,NameData+offset,sizeof(TSIG_TIME));

printf("Alg=%s\n",AlgName);

offset+=8;
offset+=ReadUINT16(NameData+offset, &len);
printf("Digest len=%d\n",len);
memcpy(SentDigest,NameData+offset,len);
SentDigest[len]=0;

offset+=len;
offset+=ReadUINT16(NameData+offset, &OrigID);
offset+=ReadUINT16(NameData+offset, &Error);
offset+=ReadUINT16(NameData+offset, &OtherData);

//decrement 'no of other records' for tsig calculation
ptr=NameData + 10;
(* (uint16_t *) ptr)=0;


/*
len=TsigOffset + 128 + StrLen(AlgName) + StrLen (KeyName) +1024;
Buffer=SetStrLen(Buffer, len);
ptr=Buffer;
memcpy(ptr,NameData,TsigOffset);
ptr+=TsigOffset;
ptr+=WriteName(ptr,Buffer+len,KeyName);

//QCLASS field.. set to 'any' (255)
*((uint16_t *) ptr)=htons(255); ptr+=sizeof(uint16_t);
//TTL.. set to zero
*((uint32_t *) ptr)=0; ptr+=sizeof(uint32_t);
//Algorithm name in canonical dns wire format
ptr+=WriteName(ptr,Buffer+len,AlgName);
memcpy(ptr,&TimeData,8);
ptr+=8;


*((uint16_t *) ptr)=Error; ptr+=sizeof(uint16_t);
*((uint16_t *) ptr)=0; ptr+=sizeof(uint16_t);

if (! Key) printf("No key!\n");
else printf("Got TSIG %s %s %d\n",Key->KeyName,AlgName,ptr-Buffer);


int fd;
fd=open("/tmp/dom-sig.out",O_WRONLY | O_CREAT | O_TRUNC,0666);
write(fd,Buffer,ptr-Buffer);
close(fd);
*/

  
Key=GetKey(KeyName);
if (! Key)
{
       	return(FALSE);
}
printf("Key %d %s\n",Key->KeyLength,Key->KeyValue);
GenerateTSIGHash(NameData, TsigOffset, AlgName, Key, &TimeData, Error, &Digest, NULL);
if (memcmp(SentDigest,Digest,MD5LEN)==0) DNSMsg->TsigAuth=TRUE;

printf("SENT DIG: ");
for (i=0; i < 16; i++) printf("%02x",SentDigest[i] & 255);
printf("\n");

printf("Calc DIG: ");
for (i=0; i < 16; i++) printf("%02x",Digest[i] & 255);
printf("\n");


DestroyString(Buffer);
DestroyString(Digest);
DestroyString(AlgName);
DestroyString(SentDigest);



return(ptr-Buffer);
}


int TSIGSignMessage(char *Algorithm, char *MsgBuff, int MsgLen, TSigKey *Key)
{
char *Digest=NULL, *TSIG=NULL;
int SigLen;
char *ptr, *rdatastart;
uint16_t *sptr, *RLenPtr;
TSIG_TIME TimeData;

TimeData.Timestamp=Now;
TimeData.Fudge=10;

printf("Key %d %s\n",Key->KeyLength,Key->KeyValue);
GenerateTSIGHash(MsgBuff, MsgLen, Algorithm, Key, &TimeData, 0, &Digest, NULL);

  ptr=MsgBuff+MsgLen;
  
  ptr+=CreateNameEntry(ptr,MsgBuff+1024,Key->KeyName,RT_TSIG);
  ptr+=WriteUINT32(ptr,0);
  RLenPtr=(uint16_t *) ptr;
  ptr+=sizeof(uint16_t);
  
  rdatastart=ptr;
  ptr+=WriteName(ptr,MsgBuff+1024,Algorithm);
  memcpy(ptr,&TimeData,sizeof(TSIG_TIME));
  ptr+=sizeof(TSIG_TIME);
  ptr+=WriteUINT16(ptr,MD5LEN);
  memcpy(ptr,Digest,MD5LEN);
  ptr+=MD5LEN;

  ptr+=WriteUINT16(ptr,0);
  ptr+=WriteUINT16(ptr,0);
  ptr+=WriteUINT16(ptr,0);
  
  
  //increment 'no of other records'
  sptr=(MsgBuff + 10);
  (*sptr)=htons(1);

 
   SigLen=ptr-(rdatastart);
   (*RLenPtr)=htons(SigLen);
printf("MsgLen=%d SigStart=%d SigLen=%d\n",ptr-MsgBuff, MsgBuff+MsgLen,SigLen);

DestroyString(Digest);

return(ptr-(MsgBuff+MsgLen));
}
