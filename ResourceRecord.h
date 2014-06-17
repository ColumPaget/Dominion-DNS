#ifndef DOM_RR_H
#define DOM_RR_H
/* WARNING WARNING, DANGER WILL ROBINSON!!                                   */
/* The 'Resource Record' type referred to here is, I believe, not really a   */
/* complete resouce record. It contains either an Address or a Host/Domain   */
/* Name, with a TimeToLive, whereas a true RR is a combination of a Name and */
/* address for a given host. I couldn't think of what else to call this item */
/* though, so there it is.                                                   */

#include <time.h>

#define AddressServer -1
#define RT_TSIG 250
#define RT_ANY 255
#define RT_NONE 0

enum RRType {none,DNSREC_ADDRESS,DNSREC_NAMESERVER, DNSREC_MAILDEST,DNSREC_MAILFORW,CNAME,SOA,DNSREC_MAILDOM,DNSREC_MAILGROUP,DNSREC_MAILRENAME,NullRecord,DNSREC_KNOWNSERVICE,DNSREC_DOMAINNAME,DNSREC_HOSTINFO,DNSREC_MAILINFO,DNSREC_MAILEXCHANGE, DNSREC_TEXT, DNSREC_RESPPERSON, DNSREC_AFSDB, DNSREC_19, DNSREC_20, DNSREC_21, DNSREC_22, DNSREC_23, DNSREC_SIG, DNSREC_KEY, DNSREC_26, DNSREC_27, DNSREC_IP6ADDRESS};

#define SRV 33 //I dont know what comes between the TXT Resource Record and this.. so I just define it here


#define CLASS_NONE 254
#define CLASS_ANY 255 // again, a big gap till this

enum RRClass {CLASS_ERROR, CLASS_INTERNET, CLASS_CSNET, CLASS_CHAOS, CLASS_HESIOD};


extern char *QueryTypeStr[];

typedef struct
{
/* This is a pointer to either a Name (char *) or address (unsigned long) */
char *Question;
char *Answer;
enum RRType Type;
int Class;
unsigned long int TTL;
time_t AddedTime;
int Pref; /*For MX records */
/* This is a general pointer to something else, used at the moment only in  */
/* the cache to point to the host item that owns this name/address          */
void *Ptr; 
int AnswerFound; //This relates to the use of this structure
		 //to express queries to the cache and other lookup
		 //systems.
} ResourceRecord;

typedef struct 
{
char *AuthSource;
char *AdminEmail;
int SerialNo;
int Refresh;
int Retry;
int Expire;
int Minimum;
} SOADataStruct;

SOADataStruct *CreateSOAStruct(char *AuthSource, char *AdminEmail, int SerialNo, int Refresh, int Retry, int Expire, int Minimum);
ResourceRecord *CreateRR(char *Question,char *Name,unsigned short Pref, unsigned long TTL, int Type, int Class);
ResourceRecord *CloneRR(ResourceRecord *);
void CopyRR(ResourceRecord *DstRR, ResourceRecord *SrcRR);
int IsIdenticalRR(ResourceRecord *RR1, ResourceRecord *RR2);
int ParseQueryType(char *String);
void DestroyRR(void *);

#endif

