#include "../DNSMessage.h"
#include "../Modules.h"
#include "../Global.h"

#define NO_OF_BUCKETS 1000




ListNode *MemHashCacheGetHead(ModuleStruct *Cache, char *Key)
{
unsigned int val;
ListNode **Buckets;

Buckets=(ListNode **) Cache->Implementation;
val=fnv_hash (Key, StrLen(Key) ) % NO_OF_BUCKETS;

if (! Buckets[val]) 
{
	Buckets[val]=ListCreate();
	ListSetFlags(Buckets[val], LIST_FLAG_SELFORG);
}

return(Buckets[val]);
}





int MemHashFindRR(ModuleStruct *Cache, ResourceRecord *RR, ListNode *Answers)
{
ListNode *Curr, *Head;
ResourceRecord *NewRR;

Head=MemHashCacheGetHead(Cache, RR->Question);
Curr=CacheTypeSimpleListSearch(Head, Cache, RR);
while (Curr)
{
	NewRR=CloneRR((ResourceRecord *) Curr->Item);
	if (NewRR->TTL==0) NewRR->TTL=Settings.DefaultTTL;
	else NewRR->TTL=(NewRR->AddedTime+NewRR->TTL) - Now;
;
	LogToFile(Settings.LogFilePath,"found cached RR %s %s %d\n",NewRR->Question,NewRR->Answer,NewRR->TTL);
	ListAddItem(Answers, NewRR);

	Curr=CacheTypeSimpleListSearch(Curr, Cache, RR);
}


}


int MemHashAddRR(ModuleStruct *Cache, ResourceRecord *RR)
{
ListNode *Head, *Curr;
ResourceRecord *NewRR;

Head=MemHashCacheGetHead(Cache, RR->Question);
Curr=CacheTypeSimpleListSearch(Head, Cache, RR);
if (Curr)
{
	NewRR=(ResourceRecord *) Curr->Item;
	CopyRR(NewRR, RR);
	NewRR->AddedTime=Now;
}
else
{
	NewRR=CloneRR(RR);
	Curr=ListAddItem(Head, NewRR);
	Curr->ItemType=NewRR->Type;
	NewRR->AddedTime=Now;
}
Cache->ItemsInCache++;


return(TRUE);
}


int ModuleInit(ModuleStruct *Cache)
{
Cache->Implementation=calloc(NO_OF_BUCKETS,sizeof(ListNode *));
Cache->Name=CopyStr(NULL,"MemHash");
Cache->AddRR=MemHashAddRR;
//Cache->Delete=CacheTypeSimpleListDeleteRR;
Cache->Search=MemHashFindRR;

return(TRUE);
}


