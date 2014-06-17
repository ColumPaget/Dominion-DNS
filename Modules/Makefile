all: HostsFile.so DhcpFile.so WinsFile.so MemHashCache.so

HostsFile.so: HostsFile.c
	gcc -shared -g -o HostsFile.so HostsFile.c

DhcpFile.so: DhcpFile.c
	gcc -shared -g -o DhcpFile.so DhcpFile.c

WinsFile.so: WinsFile.c
	gcc -shared -g -o WinsFile.so WinsFile.c

MemHashCache.so: MemHashCache.c
	gcc -shared -g -o MemHashCache.so MemHashCache.c


clean:
	@rm -f *.so
