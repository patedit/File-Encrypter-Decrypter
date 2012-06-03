/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Verifica la firma digital de un archivo
 * Plataforma:     Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.35
 * Fecha:          25-11-10
 * =========================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include "cryptlib.h"


int funcion6()
{

	int valido, tamFirma, tam, tamCert, i, status, keySize, keyMaxSize;
	long opcion_l;
	char opcion[5], *ptr, *endptr, *buffer, *rutaToCheck, *rutaFirma, *nombreFirma, *firma, *cert, *nombreCert, *rutaCert;
	FILE *ptrFileToCheck, *ptrFirma, *ptrCert;
	DIR *dir;	
	struct dirent *ent;
	struct stat st;

	/*Reservo memoria*/
	rutaToCheck=(char *)malloc(120);
	rutaFirma=(char *)malloc(120);
	nombreFirma=(char *)malloc(50);
	nombreCert=(char *)malloc(50);
	rutaCert=(char *)malloc(120);

	system("clear");
	printf("\n ------------------------------------\n");
	printf("|          Verificar firma           |\n");
	printf(" ------------------------------------\n\n");
	fflush(stdout);

	/*PASO 1. Ruta del archivo a verificar*/
	do {
		valido=0;
		printf("PASO 1. Introduzca la ruta del archivo que desea verificar: ");
		scanf("%s", rutaToCheck);
		if((ptrFileToCheck=fopen(rutaToCheck, "rb")) == NULL ) {
			printf("No se encuentra el archivo. Revise la ruta :)\n\n");
			valido=1;
			fflush(stdout);
		} 
	} while(valido==1);
	

	/*Necesitamos abrir el archivo y volcarlo a memoria*/
	stat(rutaToCheck, &st);
	tam=st.st_size;
	buffer=(char *)malloc(tam);
	fread(buffer, 1, tam, ptrFileToCheck);


	/*Buscamos el caracter '/' dentro de la cadena. Si est�, es porque el usuario meti� la ruta completa*/
	if((ptr=(strrchr(rutaToCheck, '/')))!=NULL) sprintf(nombreFirma, "%s.p7s", ptr+1); //Ruta completa
	else sprintf(nombreFirma, "%s.p7s", rutaToCheck); //El usuario meti� el nombre del archivo

	/*Ahora tengo que leer la firma. Primero la busco, y si no est�, que la seleccione el usuario*/
	dir = opendir ("./Firmas digitales/");
	if (dir != NULL) {
		i=0;
		/* Vamos a buscar los archivos .p7s que correspondan*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, nombreFirma))!=NULL) { 
				i++;
			}
		}
		closedir(dir);
	} else {
	  	/* Problemas al abrir el directorio */
	  	printf("�Ha ejecutado ya la opci�n 5?\n");
		fflush(stdout);
	  	return(-1);
	}

	if(i==0) { //Resultados = 0
		printf("\nNo se ha encontrado una firma adecuada\n");
		fflush(stdout);
		printf("Seleccione cu�l de los siguientes archivos corresponde con la firma creada en la funci�n 5:\n ");
		fflush(stdout);
		dir = opendir ("./Firmas digitales/");	
		/* Nos va a mostrar los archivos .p15 que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".p7s"))!=NULL) {
				i++; 
				printf("  %d. %s\n", i, ent->d_name);
			}
		}
		closedir(dir);
		/*El usuario introduce el n�mero que corresponde a la firma que elija*/
		do{
			valido=0;
			printf("Introduzca el n�mero de la firma que desea usar >> ");
			scanf("%s", &opcion);
			opcion_l = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l < 1 || opcion_l > i) {
				printf("Ops... tendr�s que meter un n�mero entre 1 y %d la pr�xima vez ;) Try again!\n", i);
				fflush(stdout);
				valido=1;
			}
		}while(valido==1);
		/*Guardamos el nombre del archivo correspondiente en rutaKeyset*/
		dir = opendir ("./Firmas digitales/");
		i=0;
	 	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".p7s"))!=NULL) {
				i++;
				if(opcion_l==i) { 
					sprintf(rutaFirma, "./Firmas digitales/%s", ent->d_name);
				}	
			}
		}
		closedir(dir);
		
	} else if(i==1) {
		printf("\n-> Se ha encontrado 1 firma adecuada. Se usar� la firma %s por defecto\n\n", nombreFirma);
		fflush(stdout);
		sprintf(rutaFirma, "./Firmas digitales/%s", nombreFirma);
	} 

	/*Abrimos la firma*/
	if((ptrFirma=fopen(rutaFirma, "rb")) < 0) {
		printf("Error al crear el archivo\n");
		fflush(stdout);
		return(-1);
	}
	stat(rutaFirma, &st);
	tamFirma=st.st_size;
	firma=(char *)malloc(tamFirma);
	fread(firma, 1, tamFirma, ptrFirma);

	/*Ahora necesitamos el certificado*/
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
		printf("\n��Hay %d certificados creados !!\n", i);
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
			opcion_l = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l < 1 || opcion_l > i) {
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
				if(opcion_l==i) { 
					sprintf(rutaCert, "./Claves y certificados/%s", ent->d_name);
				}	
			}
		}
		closedir(dir);
	}
	ptrCert=fopen(rutaCert, "rb");
	stat(rutaCert, &st);
	tamCert=st.st_size;
	cert=(char *)malloc(tamCert);
	fread(cert, 1, tamCert, ptrCert);

	/*Importamos certificado*/
	/*Creo el contexto para el hash*/
	CRYPT_CONTEXT contextoHash;
	if((status=cryptCreateContext(&contextoHash, CRYPT_UNUSED, CRYPT_ALGO_SHA1))!=CRYPT_OK) {
		printf("Error al crear el contexto. C�digo %d\n", status);
		fflush(stdout);
		return(-1);
	}

	/*Hash*/
	if((status=cryptEncrypt(contextoHash, buffer, tam))!=CRYPT_OK) {
		printf("Error al calcular el hash. C�digo %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptEncrypt(contextoHash, buffer, 0))!=CRYPT_OK) {
		printf("Error al calcular el hash. C�digo %d\n", status);
		fflush(stdout);
		return(-1);
	}

	CRYPT_CERTIFICATE certificado;
	if((status=cryptImportCert(cert, tamCert, CRYPT_UNUSED, &certificado))!=CRYPT_OK) {
		printf("Error al importar el certificado. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}
	if((status=cryptCheckSignature(firma, tamFirma, certificado, contextoHash))!=CRYPT_OK) {
		printf("La firma no concuerda. C�digo %d\n", status);
		fflush(stdout);
		return(-1);	
	}

	/*Destruimos contextos y cerramos lo necesario*/
	if((status=cryptDestroyContext(contextoHash))!=CRYPT_OK) {
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
