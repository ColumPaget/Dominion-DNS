#ifndef DOMINION_DNS_MESSAGE_H
#define DOMINION_DNS_MESSAGE_H

#define LITTLE_END 

#include "std_include.h"
#include "ResourceRecord.h"
#include "Settings.h"
#include <time.h>
#include <stdint.h>

typedef enum {OPCODE_QUERY, OPCODE_IQUERY, OPCODE_STATUS, OPCODE_3, OPCODE_4,
OPCODE_UPDATE}TOpCodes;


typedef struct 
{
#ifdef LITTLE_END
unsigned int WantRecurse: 1;
unsigned int Trunc: 1;
unsigned int AuthAns: 1;
unsigned int OpCode: 4;
unsigned int QR_Flag: 1;
unsigned int ResponseCode: 4;
unsigned int Z: 3;
unsigned int AllowRecurse: 1;
#else

unsigned int QR_Flag: 1;
unsigned int OpType: 4;
unsigned int AuthAns: 1;
unsigned int Trunc: 1;
unsigned int WantRecurse: 1;
unsigned int AllowRecurse: 1;
unsigned int Z: 3;
unsigned int ResponseCode: 4;
#endif

} DNSHeader;



typedef struct 
{
DNSHeader Header;
unsigned int MessageID;

unsigned int NoOfQuestions;
unsigned int NoOfZoneItems;

unsigned int NoOfAnswers;
unsigned int NoOfPrerequisites;

unsigned int NoOfNameservers;
unsigned int NoOfUpdateItems;

unsigned int NoOfOtherRecords;
unsigned int Class;
unsigned int Type;
char *Question;

ListNode *Answers;
ListNode *UpdatePrerequisites;

ListNode *Nameservers;
ListNode *UpdateItems;

ListNode *OtherRecords;


/* This is so we can instruct the caching system as to how best to treat this*/
/* item. This is important for special types of cache item like favourites   */
/* and blacklisted domains etc.                                              */


/*This is information on who sent us this packet */
uint32_t ClientIP;
char *ClientName;
uint16_t ClientPort;
int TsigAuth;
char *AnswersSourceList;
} DNSMessageStruct;

void CopyDNSMessageStruct(DNSMessageStruct *, DNSMessageStruct *);
DNSMessageStruct *CreateDNSMessageStruct();
void DestroyDNSMessageStruct(DNSMessageStruct *);
void DeleteRRList(ListNode *ListHead);

int DecodeDNSPacket(char *,DNSMessageStruct *, char *);
int CheckForPtrBytes(char *);
int ReadDNSString(char *,int,int,char *, char *);
int ParseRRSection(char *,int,char *,int *, int *, char *);
void ExtractQuadsFromAddr(char *, char [][4]);
char *DecodeAddressEntry(char *,char *);
int WriteHeader(char *Buffer,char *BuffEnd, int,int,int,int,int,DNSHeader *);
int WriteName(char *,char *,char *);
int CreateNameEntry(char *,char *, char*, short int);
int CreateAnswerEntry(char *,char *,ResourceRecord *,uint32_t);
int CreateQuestionPacket(char *,char *, char *,short int);
int WriteQuestionEntry(char *,char *,char *,short int);
int CreateDNSPacket(char *Buffer,char *BuffEnd,DNSMessageStruct *, SettingsStruct *);
int CreateResponsePacket(char *Buffer,char *BuffEnd,DNSMessageStruct *, SettingsStruct *);

int ReadUINT16(char *, int *);
int ReadUINT32(char *, int *);
#endif
