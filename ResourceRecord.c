#include "ResourceRecord.h"
#include "DNSMessage.h"
#include "Global.h"

char *QueryTypeStr[]={"none","a","ns","cname","soa", "wks", "hinfo", "mx", "txt","text",NULL};
typedef enum {QT_NONE, QT_ADDR, QT_NS, QT_CNAME, QT_SOA, QT_WKS, QT_HINFO, QT_MX, QT_TXT};

int ParseQueryType(char *String)
{
switch (MatchTokenFromList(String,QueryTypeStr,0))
{
	case QT_ADDR: return(DNSREC_ADDRESS); break;
	case QT_CNAME: return(CNAME); break;
	case QT_HINFO: return(DNSREC_HOSTINFO); break;
	case QT_SOA: return(SOA); break;
	case QT_WKS: return(DNSREC_KNOWNSERVICE); break;
	case QT_NS: return(DNSREC_NAMESERVER); break;
	case QT_MX: return(DNSREC_MAILEXCHANGE); break;
	case QT_TXT: return(DNSREC_TEXT); break;
}

return(0);
}




SOADataStruct *CreateSOAStruct(char *AuthSource, char *AdminEmail, int SerialNo, int Refresh, int Retry, int Expire, int Minimum)
{
SOADataStruct *SOA;

SOA=(SOADataStruct *) calloc(1,sizeof(SOADataStruct));
SOA->AuthSource=CopyStr(NULL,AuthSource);
SOA->AdminEmail=CopyStr(NULL,AdminEmail);
SOA->SerialNo=SerialNo;
SOA->Refresh=Refresh;
SOA->Retry=Retry;
SOA->Expire=Expire;
SOA->Minimum=Minimum;

return(SOA);
}



ResourceRecord *CreateRR(char *Question, char *Answer, unsigned short Pref, unsigned long TTL, int Type, int Class)
{
ResourceRecord *NewRR;

NewRR=(ResourceRecord *) calloc(1,sizeof(ResourceRecord));
NewRR->Question=CopyStr(NULL, Question);
NewRR->Answer=CopyStr(NULL, Answer);
NewRR->TTL=TTL;
NewRR->Pref=Pref;
NewRR->Type=Type;
NewRR->Class=Class;

return(NewRR);
}



void CopyRR(ResourceRecord *DstRR, ResourceRecord *SrcRR)
{
SOADataStruct *SoaData;

	DstRR->Question=CopyStr(DstRR->Question, SrcRR->Question);
	DstRR->Answer=CopyStr(DstRR->Answer, SrcRR->Answer);
	DstRR->TTL=SrcRR->TTL;
	DstRR->Pref=SrcRR->Pref;
	DstRR->Type=SrcRR->Type;
	DstRR->Class=SrcRR->Class;
	DstRR->Ptr=SrcRR->Ptr;

	if (SrcRR->Type == SOA)
	{
	  SoaData=SrcRR->Ptr;
	  if (SoaData) DstRR->Ptr=CreateSOAStruct(SoaData->AuthSource, SoaData->AdminEmail, SoaData->SerialNo, SoaData->Refresh, SoaData->Retry, SoaData->Expire, SoaData->Minimum);
	}
	
}



ResourceRecord *CloneRR(ResourceRecord *InRR)
{
ResourceRecord *RR;
SOADataStruct *SoaData;

RR=CreateRR(InRR->Question,InRR->Answer,InRR->Pref,InRR->TTL, InRR->Type, InRR->Class);
RR->AddedTime=InRR->AddedTime;

if (RR->Type == SOA)
{
  SoaData=InRR->Ptr;
	if (SoaData) RR->Ptr=CreateSOAStruct(SoaData->AuthSource, SoaData->AdminEmail, SoaData->SerialNo, SoaData->Refresh, SoaData->Retry, SoaData->Expire, SoaData->Minimum);
}


return(RR);
}



int NameMatch(char *N1, char *N2)
{
if (strcasecmp(N1,N2)==0) return(TRUE);
if (strcasecmp(N1,"*")==0) return(TRUE);
if (strcasecmp(N2,"*")==0) return(TRUE);
return(FALSE);
}

int IsIdenticalRR(ResourceRecord *RR1, ResourceRecord *RR2)
{
   if (
        ((RR1->Type==RT_ANY) || (RR1->Type==RR2->Type))  &&
        (RR1->Pref==RR2->Pref) &&
	(NameMatch(RR1->Question,RR2->Question)) &&
	(NameMatch(RR1->Answer,RR2->Answer)) 
      ) return(TRUE);
return(FALSE);
}

void DestroyRR(void *inptr)
{
ResourceRecord *RR;
SOADataStruct *SoaData;

RR=(ResourceRecord *) inptr;
if (RR->Question !=NULL) free(RR->Question);
if (RR->Answer !=NULL) free(RR->Answer);
if (RR->Type == SOA)
{
  SoaData=RR->Ptr;

  if (SoaData)
  {
     if (SoaData->AuthSource) free(SoaData->AuthSource);
     if (SoaData->AdminEmail) free(SoaData->AdminEmail);
     free(SoaData);
  }
}

free(RR);
}



