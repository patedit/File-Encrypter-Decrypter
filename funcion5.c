/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Firma digitalmente un archivo
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


int funcion5()
{
	int i, status, valido, tam, longFirma, longFirmaMax;
	long opcion_l;
	char opcion[5], *ptr, *endptr, *buffer, *rutaToHash, *nombreKeyset, *rutaKeyset, *password, *dirFirmas, *rutaFirma;
	void *firma;
	FILE *ptrFileToHash, *ptrFirma;
	DIR *dir;
	struct stat st;
	struct dirent *ent;


	/*Reservo memoria*/
	rutaToHash=(char *)malloc(120);
	nombreKeyset=(char *)malloc(50);
	rutaKeyset=(char *)malloc(120);
	password=(char *)malloc(20);
	dirFirmas=(char *)malloc(80);
	rutaFirma=(char *)malloc(120);

	system("clear");
	printf("\n ------------------------------------\n");
	printf("|          Firmar un archivo         |\n");
	printf(" ------------------------------------\n\n");
	fflush(stdout);
	/*PASO 1. Ruta del archivo a firmar*/
	do {
		valido=0;
		printf("PASO 1. Introduzca la ruta del archivo que desea firmar: ");
		scanf("%s", rutaToHash);
		if((ptrFileToHash=fopen(rutaToHash, "rb")) == NULL ) {
			printf("No se encuentra el archivo. Revise la ruta :)\n\n");
			valido=1;
			fflush(stdout);
		} 
	} while(valido==1);

	/*Necesitamos abrir el archivo y volcarlo a memoria*/
	stat(rutaToHash, &st);
	tam=st.st_size;
	buffer=(char *)malloc(tam);
	fread(buffer, 1, tam, ptrFileToHash);


	/*Abrimos el keyset*/
	dir = opendir ("./Claves y certificados/");
	if (dir != NULL) {
		i=0;
		/* Nos va a mostrar los archivos .p15 que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".p15"))!=NULL) { 
				strcpy(nombreKeyset, ent->d_name);
				i++;
			}
		}
		closedir(dir);
	} else {
	  	/* Problemas al abrir el directorio */
	  	printf("¿Ha ejecutado ya la opción 1?\n");
		fflush(stdout);
	  	return(-1);
	}

	if(i==0) {
		printf("\nNo se ha encontrado ningún archivo keyset. (¿Ha ejecutado ya la opción 1?)\n");
		fflush(stdout);
		return(-1);
	} else if(i==1) {
		printf("\n-> Se ha encontrado 1 archivo keyset. Se usará %s por defecto\n\n", nombreKeyset);
		fflush(stdout);
		sprintf(rutaKeyset, "./Claves y certificados/%s", nombreKeyset);
	} else {
		printf("\n¡¡ Hay %d archivos keysets creados !!\n", i);
		i=0;
		dir = opendir ("./Claves y certificados/");	
		/* Nos va a mostrar los archivos .p15 que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".p15"))!=NULL) {
				i++; 
				printf("  %d. %s\n", i, ent->d_name);
			}
		}
		closedir(dir);
		/*El usuario introduce el número que corresponde al archivo keyset que elija*/
		do{
			valido=0;
			printf("Introduzca el número del archivo keyset que desea usar >> ");
			scanf("%s", &opcion);
			opcion_l = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l < 1 || opcion_l > i) {
				printf("Ops... tendrás que meter un número entre 1 y %d la próxima vez ;) Try again!\n", i);
				fflush(stdout);
				valido=1;
			}
		}while(valido==1);
		/*Guardamos el nombre del archivo correspondiente en rutaKeyset*/
		dir = opendir ("./Claves y certificados/");
		i=0;
	 	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".p15"))!=NULL) {
				i++;
				if(opcion_l==i) { 
					sprintf(rutaKeyset, "./Claves y certificados/%s", ent->d_name);
				}	
			}
		}
		closedir(dir);
	}

	/*PASO 2. Password*/
	do {
		valido=0;
		printf("\nPASO 2. Introduzca la contraseña: ");
		scanf("%s", password);
		if((strlen(password))<2) {
			printf("\nLa contraseña ha de tener más de un caracter\n");
			fflush(stdout);	
			valido=1;
		}
	}while(valido==1);

	/*Creo el contexto para el hash*/
	CRYPT_CONTEXT contextoHash, contextoFirma;
	if((status=cryptCreateContext(&contextoHash, CRYPT_UNUSED, CRYPT_ALGO_SHA1))!=CRYPT_OK) {
		printf("Error al crear el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	/*Hash*/
	if((status=cryptEncrypt(contextoHash, buffer, tam))!=CRYPT_OK) {
		printf("Error al calcular el hash. CÃ³digo %d\n",status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptEncrypt(contextoHash, buffer, 0))!=CRYPT_OK) {
		printf("Error al calcular el hash. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	CRYPT_KEYSET keyset;
	if((status=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, rutaKeyset, CRYPT_KEYOPT_READONLY))!=CRYPT_OK) {
		printf("Error al abrir keyset. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptCreateContext(&contextoFirma, CRYPT_UNUSED, CRYPT_ALGO_RSA))!=CRYPT_OK) {
		printf("Error al crear contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptGetPrivateKey(keyset, &contextoFirma, CRYPT_KEYID_NAME, "claveRSA", password))!=CRYPT_OK) {
		printf("Es muy posible que hayas metido mal la contraseña. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	if((status=cryptCreateSignature(NULL, 0, &longFirmaMax, contextoFirma, contextoHash))!=CRYPT_OK) {
		printf("Error al crear la firma. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	firma=malloc(longFirmaMax);
	if((status=cryptCreateSignature(firma, longFirmaMax, &longFirma, contextoFirma, contextoHash))!=CRYPT_OK) {
		printf("Error al crear la firma. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	/*Vamos a guardar la firma en un archivo*/
	/*Compruebo que exista el directorio. Si lstat devuelve 0 es que existe. Si devuelve otro valor hay que crear el directorio*/
	sprintf(dirFirmas, "./Firmas digitales");
	if (status = lstat(dirFirmas, &st) != 0) {
		if(status=mkdir(dirFirmas, 0777) != 0) {
			printf("Error al crear el dirClaves\n");
			fflush(stdout);
			return(-1);
		}
	}
	/*Buscamos el caracter '/' dentro de la cadena. Si está, es porque el usuario metió la ruta completa*/
	if((ptr=(strrchr(rutaToHash, '/')))!=NULL) sprintf(rutaFirma, "./Firmas digitales/%s.p7s", ptr+1); //Ruta completa
	else sprintf(rutaFirma, "./Firmas digitales/%s.p7s", rutaToHash); //El usuario metió el nombre del archivo

	/*Abrimos*/
	if((ptrFirma=fopen(rutaFirma, "wb")) < 0) {
		printf("Error al crear el archivo\n");
		fflush(stdout);
		return(-1);
	}
	/*Escribimos el archivo*/
	if((status=fwrite(firma, 1, longFirma, ptrFirma))!=longFirma) {
		printf("Error al guardar la firma\n");
		fflush(stdout);
		return(-1);
	}
	/*Destruimos los contextos y cerramos el keyset*/
	fclose(ptrFirma);
	if((status=cryptKeysetClose(keyset))!=CRYPT_OK) {
		printf("Error al cerrar el keyset. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	if((status=cryptDestroyContext(contextoHash))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	if((status=cryptDestroyContext(contextoFirma))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	return(0);

}
