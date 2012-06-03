/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Generaci�n de clave sim�trica
 * Plataforma:     Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.352
 * Fecha:          14-10-10
 * =========================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include "cryptlib.h"


int funcion2()
{
	int status, valido, keyMaxSize, keySize, tam, i;
	long int opcion_l, opcion_l2;
	char opcion[5], *claveExportada, *buffer, *cert, *endptr, *ptr, *nombreCert, *rutaCert, *nombreSim, *rutaSim;
	FILE *ptrCert, *ptrSim;
	DIR *dir;
	struct stat st;
	struct dirent *ent;

	/*Reservo memoria*/
	nombreCert=(char *)malloc(20);
	rutaCert=(char *)malloc(80);
	nombreSim=(char *)malloc(20);
	rutaSim=(char *)malloc(80);

	system("clear");
	printf("\n ------------------------------------\n");
	printf("|     Generaci�n de clave sim�trica  |\n");
	printf(" ------------------------------------\n\n");
	fflush(stdout);
	/*PASO 1. Se escoje el tipo de clave*/
	printf("PASO 1. Seleccione el tipo de clave que desee usar:\n");
	printf("  1. AES (por defecto) \n");
	printf("  2. DES \n");
	fflush(stdout);

	do{
		printf("Elija la opci�n que desee (Introduzca 0 para usar la opci�n por defecto) >> ");
		fflush(stdout);
		scanf ("%s", &opcion);
		valido=0;
		/*Comprobacion de la validez de la selecci�n (que sea un n�mero)
		(usando strtol, si hay algun caracter no num�rico, endptr apunta al primero de ellos,
		lo cual implica que si la cadena apuntada por endptr no tiene longitud 0
		es porque se ha introducido un caracter no num�rico)*/
		opcion_l = strtol(opcion,&endptr,10);
		if(strlen(endptr)!=0 || opcion_l < 0 || opcion_l > 2) {
			printf("Ops... tendr�s que meter un n�mero entre 0 y 2 la pr�xima vez ;) Try again!\n");
			fflush(stdout);
			valido=1;
		}
	} while(valido==1);


	/*Comprobamos qu� cifrado se va a usar y creamos el contexto*/
	CRYPT_CONTEXT contextoSesion;
	if(opcion_l==1 || opcion_l==0) status=cryptCreateContext(&contextoSesion, CRYPT_UNUSED, CRYPT_ALGO_AES); //AES		
	else if(opcion_l==2) status=cryptCreateContext(&contextoSesion, CRYPT_UNUSED, CRYPT_ALGO_DES); //DES	
	if(status!=CRYPT_OK) {
		printf("Error al crear el contexto. C�digo %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptGenerateKey(contextoSesion))!=CRYPT_OK) { //Crea una clave y la deja en ese contexto
		printf("Error al generar una clave. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}

	/*PASO 2. Pedimos el nombre del archivo*/
	printf("\nPASO 2. Introduzca el nombre del archivo que desea generar: ");
	scanf("%s", nombreSim);
	if(opcion_l==0 || opcion_l==1) sprintf(rutaSim, "./Claves y certificados/%s.aes", nombreSim); 
	if(opcion_l==2) sprintf(rutaSim, "./Claves y certificados/%s.des", nombreSim);

	/*Abrimos el certificado*/
	dir = opendir ("./Claves y certificados/");
	if (dir != NULL) {
		i=0;
		/* Nos va a mostrar los archivos que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".cert"))!=NULL) { 
				strcpy(nombreCert, ent->d_name);
				i++;
			}
		}
		closedir(dir);
	} else {
	  	/* Problemas al abrir el directorio */
	  	printf("�Ha ejecutado ya la opci�n 1?\n");
		fflush(stdout);
	  	return(-1);
	}
	if(i==0) {
		printf("No se ha encontrado ning�n certificado. (�Ha ejecutado ya la opci�n 1?)\n");
		fflush(stdout);
		return(-1);
	} else if(i==1) {
		printf("\n-> Se ha encontrado 1 certificado. Se usar� el certificado %s por defecto\n\n", nombreCert);
		fflush(stdout);
		sprintf(rutaCert, "./Claves y certificados/%s", nombreCert);
	} else {
		printf("\n��Hay %d certificados creados!!\n", i);
		fflush(stdout);
		i=0;
		dir = opendir ("./Claves y certificados/");	
		/* Nos va a mostrar los archivos que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".cert"))!=NULL) {
				i++; 
				printf("  %d. %s\n", i, ent->d_name);
			}
		}
		closedir(dir);
	
		do{
			valido=0;
			printf("Introduzca el n�mero del certificado que desea usar >> ");
			scanf("%s", &opcion);
			opcion_l2 = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l2 < 1 || opcion_l2 > i) {
				printf("Ops... tendr�s que meter un n�mero entre 1 y %d la pr�xima vez ;) Try again!\n", i);
				fflush(stdout);
				valido=1;
			}
		}while(valido==1);

		/*Guardamos el nombre del archivo correspondiente en rutaCert*/
		dir = opendir ("./Claves y certificados/");
		i=0;
	 	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".cert"))!=NULL) {
				i++;
				if(opcion_l2==i) { 
					sprintf(rutaCert, "./Claves y certificados/%s", ent->d_name);
				}	
			}
		}
		closedir(dir);
	}


	/*Escribimos el archivo certificado a buffer*/
	if((ptrCert=fopen(rutaCert, "rb")) == NULL ) {
		printf("Compruebe que haya generado ya una clave p�blica\n");
		fflush(stdout);
		return(-1);
	}
	stat(rutaCert, &st);
	tam=st.st_size;
	buffer=(char *)malloc(tam);
	status=fread(buffer, 1, tam, ptrCert);

	/*Importamos certificado y creamos la clave de sesi�n*/
	CRYPT_CERTIFICATE certificado;
	if((status=cryptImportCert(buffer, tam, CRYPT_UNUSED, &certificado))!=CRYPT_OK) {
		printf("Error al importar el certificado. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}
	if((status=cryptExportKey(NULL, 0, &keyMaxSize, certificado, contextoSesion))!=CRYPT_OK) {
		printf("Error al exportar la clave. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}
	claveExportada=(char *)malloc(keyMaxSize);
	if((status=cryptExportKey(claveExportada, keyMaxSize, &keySize, certificado, contextoSesion))!=CRYPT_OK) {
		printf("Error al exportar la clave. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}

	/*Guardamos en un archivo la clave de sesi�n*/
	if((ptrSim=fopen(rutaSim, "wb")) == NULL) {
		printf("Error al crear el archivo\n");
		fflush(stdout);
		return(-1);
	}

	if((status=fwrite(claveExportada, 1, keySize, ptrSim))!=keySize) {
		printf("Error al guardar la clave sim�trica\n");
		fflush(stdout);
		return(-1);
	}


	/*Cerramos los descriptores y destruimos contextos y certificados*/
	fclose(ptrSim);
	fclose(ptrCert);
	if((status=cryptDestroyContext(contextoSesion))!=CRYPT_OK) {
		printf("Error al destruir el contexto. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}
	if((status=cryptDestroyCert(certificado))!=CRYPT_OK) {
		printf("Error al destruir el certificado. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}

	
	return(0);
}
