#include "Cache.h"
#include "Modules.h"

ModuleStruct **Caches;
ListNode *CacheTypes=NULL;



ListNode *CacheTypeSimpleListSearch(ListNode *Head, ModuleStruct *Cache, ResourceRecord *RR)
{
ListNode *Curr, *Next;
ResourceRecord *FoundRR;
int count=0;
struct timeval start, end;

gettimeofday(&start,NULL);
Curr=ListGetNext(Head);
while (Curr)
{
	FoundRR=(ResourceRecord *) Curr->Item;
	Next=ListGetNext(Curr);

	if ((Cache->Flags & CACHE_ITEMS_EXPIRE) && (FoundRR->TTL > 0) && ( (FoundRR->AddedTime + FoundRR->TTL) <= Now))
	{
		DestroyRR(FoundRR);
		ListDeleteNode(Curr);
		if (Cache->ItemsInCache >0) Cache->ItemsInCache--;
	}
	else if (Curr->ItemType==RR->Type)
	{
		if (strcmp(FoundRR->Question,RR->Question)==0) 
		{
			gettimeofday(&end,NULL);
			return(Curr);
		}
	}
	count++;
	Curr=Next;
}

return(NULL);
}



int CacheTypeSimpleListFindRR(ModuleStruct *Cache, ResourceRecord *RR, ListNode *Answers)
{
ListNode *Curr, *Next;
ResourceRecord *NewRR;

Curr=CacheTypeSimpleListSearch((ListNode *) Cache->Implementation, Cache, RR);
while (Curr)
{
	Next=CacheTypeSimpleListSearch(Curr, Cache, RR);
	NewRR=CloneRR((ResourceRecord *) Curr->Item);
	if (NewRR->TTL==0) NewRR->TTL=Settings.DefaultTTL;
	else NewRR->TTL=(NewRR->AddedTime+NewRR->TTL) - Now;
;
	LogToFile(Settings.LogFilePath,"found cached RR %s %s %d\n",NewRR->Question,NewRR->Answer,NewRR->TTL);
	ListAddItem(Answers, NewRR);

	//ListSwapItems(Curr->Prev,Curr);
	Curr=Next;
}

return(ListSize(Answers));
}


int CacheTypeSimpleListAddRR(ModuleStruct *Cache, ResourceRecord *RR)
{
ListNode *Curr;
ResourceRecord *NewRR;

Curr=CacheTypeSimpleListSearch((ListNode *) Cache->Implementation, Cache, RR);
if (Curr && IsIdenticalRR(RR, (ResourceRecord *) Curr->Item))
{
   NewRR=(ResourceRecord *) Curr->Item;
   CopyRR(NewRR, RR);
   NewRR->AddedTime=Now;
}
else
{
  NewRR=CloneRR(RR);
  Curr=ListAddItem((ListNode *) Cache->Implementation,NewRR);
	Curr->ItemType=NewRR->Type;
  NewRR->AddedTime=Now;
}
Cache->ItemsInCache++;

return(TRUE);
}


ModuleStruct *CacheTypeSimpleListInit()
{
ModuleStruct *Cache;

Cache=(ModuleStruct *) calloc(1 , sizeof(ModuleStruct));
Cache->Implementation=(void *) ListCreate();
Cache->Name=CopyStr(NULL,"SimpleList");
Cache->AddRR=CacheTypeSimpleListAddRR;
//Cache->DelRR=CacheTypeSimpleListDeleteRR;
Cache->Search=CacheTypeSimpleListFindRR;
//Cache->Init=CacheTypeSimpleListInit;

return(Cache);
}



int CacheProcessQuery(ModuleStruct *LS, char *Question, DNSMessageStruct *Query)
{
ResourceRecord *RR=NULL;
ListNode *Curr=NULL;
int result;


  RR=CreateRR(Question,"",0,0,Query->Type,CLASS_INTERNET);
  result=CacheFindMatchRR(RR,CI_DNSUPDATE,Query->Answers);

	LogToFile(Settings.LogFilePath,"UPC: %s %d\n",Question,result);
  if (result < 1) 
  {  
      result=CacheFindMatchRR(RR,CI_QUERY,Query->Answers);
  }

  if (result)
  {
	Query->NoOfAnswers=ListSize(Query->Answers);
  }

// we get rid of our query RR here, so we can re-use the RR variable!
  DestroyRR(RR);




//if we have a PTR query, we have to change our address answers to
//PTR answers
if (Query->Type==DNSREC_DOMAINNAME)
{
	Curr=ListGetNext(Query->Answers);
	while (Curr)
	{
		RR=(ResourceRecord *) Curr->Item;
		if (RR->Type==DNSREC_ADDRESS) 
		{
			RR->Type=DNSREC_DOMAINNAME;
			RR->Answer=CopyStr(RR->Answer,RR->Question);
			RR->Question=CopyStr(RR->Question,Question);
		}
		Curr=ListGetNext(Curr);
	}
}


 return(result); 
}




void CacheInit()
{
int count;
ModuleStruct *NewModEntry;

if (Caches) return;


Caches=(ModuleStruct **) calloc(NoOfCaches +1 , sizeof(ModuleStruct *));
for (count=0; count < NoOfCaches; count++) 
{
	Caches[count]=CacheTypeSimpleListInit();
	if (count==CI_QUERY) Caches[count]->Flags |=CACHE_ITEMS_EXPIRE;
}

NewModEntry=(ModuleStruct *) CreateModuleStruct();
NewModEntry->Name="Cache";
NewModEntry->Search=CacheProcessQuery;
ListAddItem(LookupSourceList,NewModEntry);
}


//Any caches that, for instance, require reading/writing files to disk
//are 'opened' by this function, which is called after chroot so that any
//such files are in the chrooted directory
void CacheOpenAll()
{
int count;

for (count=0; count < NoOfCaches; count++) 
{
	if (Caches[count]->Open) Caches[count]->Open(Caches[count]);
}

}





void CacheLoadModule(ModuleStruct *Module, int Type)
{
if (! Caches) CacheInit();
Caches[Type]=Module;
if (Type==CI_QUERY) Caches[Type]->Flags |=CACHE_ITEMS_EXPIRE;
}




int CacheAddRRList(ListNode *List, int ItemType)
{
ListNode *Curr;
ResourceRecord *RR;

Curr=ListGetNext(List);
while (Curr)
{
   RR=(ResourceRecord *) Curr->Item;
   CacheAddRR(RR,ItemType);
   Curr=ListGetNext(Curr);
}
return(TRUE);
}

int CacheAddDNSMessage(DNSMessageStruct *Item, int ItemType)
{
if (ItemType >= NoOfCaches) return(FALSE);
CacheAddRRList(Item->Answers, ItemType);
CacheAddRRList(Item->Nameservers, ItemType);
return(TRUE);
}

int CacheFindProcessCNAMES(ResourceRecord *InRR, ListNode *AnswersList, int ItemType)
{
ListNode *Curr;
ResourceRecord *RR, *TmpRR;
int result=FALSE;

Curr=ListGetNext(AnswersList);
while (Curr)
{
RR=(ResourceRecord *) Curr->Item;
if (
	(RR->Type==CNAME) &&
	(strcmp(InRR->Question,RR->Question)==0)
   )
{
    TmpRR=CreateRR(RR->Answer, "", 0,0,InRR->Type,CLASS_INTERNET);
    /* ugh! recursion.. beware! */
    result=Caches[ItemType]->Search(Caches[ItemType], TmpRR, AnswersList);
    // we may not have found a proper match, but maybe we found a cname
    // so check those, if we get a positive result from those, then we
    // want to return 'TRUE'
    if (CacheFindProcessCNAMES(TmpRR, AnswersList, ItemType)) result=TRUE;

    DestroyRR(TmpRR);
}

Curr=ListGetNext(Curr);
}

return(result);
}


int CacheAddRR(ResourceRecord *RR, int ItemType)
{
ResourceRecord *tmpRR;

if (! RR) return(FALSE);
if (ItemType >= NoOfCaches) return(FALSE);


tmpRR=CloneRR(RR);

if (! tmpRR) return(FALSE);

if (RR->Type==DNSREC_DOMAINNAME)
{
  tmpRR->Question=DecodeAddressEntry(tmpRR->Question,RR->Question);
}

if (Caches[ItemType]->AddRR) Caches[ItemType]->AddRR(Caches[ItemType], tmpRR);

DestroyRR(tmpRR);
return(TRUE);
}


int CacheFindMatchRR(ResourceRecord *RR, int ItemType, ListNode *RRList)
{
int result=FALSE;

if (ItemType >= NoOfCaches) return(FALSE);
if (! Caches[ItemType]) return(FALSE);
if (! Caches[ItemType]->Search) return(FALSE);


result=Caches[ItemType]->Search(Caches[ItemType],RR, RRList);
if (CacheFindProcessCNAMES(RR, RRList, ItemType)) result=TRUE;
	  
return(result);
}



int CacheFindMatchDNSMessage(DNSMessageStruct *Query, int ItemType, ListNode *RRList)
{
ResourceRecord *RR;

if (ItemType >= NoOfCaches) return(FALSE);
RR=CreateRR(Query->Question, "", 0,0, Query->Type,CLASS_INTERNET);
CacheFindMatchRR(RR, ItemType, RRList);
DestroyRR(RR);
return(TRUE);
}



int CacheDeleteRR(ResourceRecord *RR, int ItemType)
{
int result;

if (ItemType >= NoOfCaches) return(FALSE);
  result=Caches[ItemType]->DelRR(Caches[ItemType], RR);
return(result);
}
