PRINCIPAL = main
FICHERO1 = funcion1
FICHERO2 = funcion2
FICHERO3 = funcion3
FICHERO4 = funcion4
FICHERO5 = funcion5
FICHERO6 = funcion6
FICHERO7 = cesarEncrypt
FICHERO8 = cesarDecrypt

FICHEROS-FUENTE =	$(PRINCIPAL).c $(FICHERO1).c $(FICHERO2).c $(FICHERO3).c $(FICHERO4).c $(FICHERO5).c $(FICHERO6).c $(FICHERO7).c $(FICHERO8).c
FICHERO-EJECUTABLE =	$(PRINCIPAL)


LIBNAME=/home/labs/rsc/soft/lib/libcl.a
CC = gcc
LIBS = -lpthread  -lresolv -ldl
TARGET= $(LIBNAME)


all:	$(FICHERO-EJECUTABLE)

$(FICHERO-EJECUTABLE):	$(PRINCIPAL).o 
			$(CC) $(FICHEROS-FUENTE) -o $@ -I/home/labs/rsc/soft/cryptlib $(TARGET) $(LIBS) 

$(PRINCIPAL).o:		$(PRINCIPAL).c  
			$(CC) -c $(PRINCIPAL).c -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO1).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO2).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO3).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO4).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO5).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO6).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO7).c  -I/home/labs/rsc/soft/cryptlib
			$(CC) -c $(FICHERO8).c  -I/home/labs/rsc/soft/cryptlib

clean:
	rm *.o
	rm $(FICHERO-EJECUTABLE)
