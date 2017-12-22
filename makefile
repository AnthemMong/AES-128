project = aes-128.o test.o table.o

a.out : $(project)
	gcc $(project)
test.o : aes-128.c test.c table.c
	gcc -c aes-128.c test.c table.c
aes-128.o : aes-128.c table.c aes-128.h
	gcc -c aes-128.c table.c
table.o : table.c aes-128.h
	gcc -c table.c

clean : 
	rm $(project)