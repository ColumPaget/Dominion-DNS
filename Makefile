SHARED_LIB=-lUseful-2.0

LIBS1=-ldl

#ifdef $(SHARED_LIB)
#@ echo "Shared lib defined"
#LIBS=$(LIBS1) $(SHARED_LIB)
#else 
#LIBS=$(LIBS1)
#endif

LIBS=$(LIBS1) $(SHARED_LIB)

OBJ1=ResourceRecord.o DNSMessage.o RemoteServers.o URL.o ConfigFile.o Global.o LocalDomains.o DialupLink.o Alias.o Comms.o Modules.o Manage.o Cache.o Tcp.o HandleQuery.o TSIG.o ACL.o 

#lib/md5/md5c.o lib/base64/base64.o

ifdef STATIC_LIB
OBJ=$(OBJ1) $(STATIC_LIB)
else
OBJ=$(OBJ1)
endif


#FLAGS=-I./include/
#FLAGS=-I/usr/local/include
#DYNFLAG=-DNONDYNAMIC

#if you want to use libColum shared then delete $(STATIC_LIB) and add $(SHARED_LIB)

all: dominion updater

dominion: $(OBJ) dominion.c 
	gcc $(FLAGS) -rdynamic $(LIBS) -g -o dom $(OBJ) dominion.c 

non-dynamic: $(OBJ) dominion.c
	gcc $(SHARED_LIB) $(DYNFLAG) -g -o dom $(OBJ) Modules/HostsFile.so  dominion.c


updater: $(OBJ) Updater.c 
	gcc $(FLAGS) -rdynamic $(LIBS) -g -o updater $(OBJ) Updater.c $(SHARED_LIB)


DNSEntry.o:DNSEntry.h DNSEntry.c
	gcc $(FLAGS) -g -c DNSEntry.c

ResourceRecord.o:ResourceRecord.h ResourceRecord.c
	gcc $(FLAGS) -g -c ResourceRecord.c

DNSMessage.o: DNSMessage.h DNSMessage.c
	gcc $(FLAGS) -g -c DNSMessage.c

RemoteServers.o: RemoteServers.h RemoteServers.c
	gcc $(FLAGS) -g -c RemoteServers.c

URL.o: URL.h URL.c
	gcc $(FLAGS) -g -c URL.c


ConfigFile.o: ConfigFile.h ConfigFile.c
	gcc $(FLAGS) -g -c ConfigFile.c

Global.o: Global.h Global.c
	gcc $(FLAGS) -g -c Global.c

LocalDomains.o: LocalDomains.h LocalDomains.c
	gcc $(FLAGS) -g -c LocalDomains.c

DialupLink.o: DialupLink.h DialupLink.c
	gcc $(FLAGS) -g -c DialupLink.c

Alias.o: Alias.h Alias.c
	gcc $(FLAGS) -g -c Alias.c

Comms.o: Comms.h Comms.c
	gcc $(FLAGS) -g -c Comms.c

Modules.o: Modules.h Modules.c
	gcc $(FLAGS) $(DYNFLAG) -g -c Modules.c

Manage.o: Manage.h Manage.c
	gcc $(FLAGS) -g -c Manage.c

Cache.o: Cache.h Cache.c
	gcc $(FLAGS) -g -c Cache.c

ACL.o: ACL.h ACL.c
	gcc $(FLAGS) -g -c ACL.c

Tcp.o: Tcp.h Tcp.c
	gcc $(FLAGS) -g -c Tcp.c

TSIG.o: TSIG.h TSIG.c
	gcc $(FLAGS) -g -c TSIG.c

HandleQuery.o: HandleQuery.h HandleQuery.c
	gcc $(FLAGS) -g -c HandleQuery.c


clean:
	@rm -f *.o lib/*/*.o
