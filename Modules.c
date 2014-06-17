#include "Modules.h"
#include <dlfcn.h>
#include <glob.h>

ListNode *LookupModulesList=NULL;
ListNode *ModuleSettings=NULL;


void LoadModule(ModuleStruct *Mod)
{
#ifndef NONDYNAMIC
void *libhandle;
MOD_INIT_FUNC LoadFunc;


libhandle=dlopen(Mod->ModulePath,RTLD_LAZY);
if (libhandle==NULL) 
{
printf("error: %s\n",dlerror());
printf("Failed to load %s\n",Mod->ModulePath);
}
LoadFunc=(MOD_INIT_FUNC) dlsym(libhandle,"ModuleInit");
if (LoadFunc) (*LoadFunc)(Mod);

printf("Load %s %d\n",Mod->ModulePath, LoadFunc);

#endif
}


ModuleStruct *CreateModuleStruct()
{
ModuleStruct *Module;

Module=(ModuleStruct *) calloc(1,sizeof(ModuleStruct));
return(Module);
}

