#include "Alias.h"
#include "Global.h"

char *GetAlias(char *Name)
{
ListNode *Curr;
ResourceRecord *AliasItem;

Curr=ListGetNext(AliasListHead);
while (Curr)
{
AliasItem=(ResourceRecord *)Curr->Item;
if (strcasecmp(AliasItem->Question,Name)==0) return(AliasItem->Answer);

Curr=ListGetNext(Curr);
}

return(Name);


}

