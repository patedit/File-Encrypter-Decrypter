/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Desencripta de forma transparente al usuario cualquier archivo previamente encriptado.
 * Plataforma:     Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.35
 * Fecha:          4-11-10
 * =========================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include "cryptlib.h"


extern char* cesarDecrypt(char cadena[], int pos, char cabecera1[]);

int funcion4()
{
	int keySize, tam, tamRelleno, status, valido, i;
	long int opcion_l, tamRelleno_l;
	char opcion[5], *claveDecrypt, *buffer, *ptr, *endptr, 
*rutaToDecrypt, *fileToDecrypt, *rutaKeyset, *nombreKeyset, 
*bytesReaded, *cabecera1, *cabecera2, *varlocal, *varlocal2, *password, 
*directorio, *busSim, *rutaSim, *nombreSim, *rutaDecrypted, *bytesRelleno;
	FILE *ptrSim, *ptrDecrypted, *ptrEncrypted;
	DIR *dir;
	struct dirent *ent;	
	struct stat st;

	/*Reservo memoria*/
	bytesReaded=(char *)malloc(3);
	bytesRelleno=(char *)malloc(2);
	rutaSim=(char *)malloc(120);	
	rutaDecrypted=(char *)malloc(120);	
	nombreSim=(char *)malloc(40);	
	busSim=(char *)malloc(4);	
	rutaKeyset=(char *)malloc(120);			
	fileToDecrypt=(char *)malloc(40);
	rutaToDecrypt=(char *)malloc(120);
	directorio=(char *)malloc(120);
	varlocal=(char *)malloc(3);
	varlocal2=(char *)malloc(3);
	password=(char *)malloc(50);
	nombreKeyset=(char *)malloc(50);
	cabecera1=(char *)malloc(3);
	cabecera2=(char *)malloc(3);

	system("clear");
	printf("\n ------------------------------------\n");
	printf("|        Descifrar un archivo        |\n");
	printf(" ------------------------------------\n\n");
	fflush(stdout);


	/*Paso 1. Tengo que abrir el archivo a desencriptar y leer los primeros bytes*/
	dir = opendir ("./Archivos encriptados/");
	if (dir != NULL) {
		i=0;
		/*Vamos a ver si hay algún archivo en la carpeta y contar cuantos hay*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".enc"))!=NULL) { //Solo los archivos encriptados
				i++;
				strcpy(fileToDecrypt, ent->d_name);
			}
		}
		closedir(dir);
	} else {
	  	/* Problemas al abrir el directorio */
		printf("Error al mostrar los archivos. Â¿Ha ejecutado ya la opciÃ³n 3?\n");
		fflush(stdout);
	  	return(-1);
	}
	if(i==0) {
		printf("No hay ningún archivo disponible para encriptar. Ejecute primero la opciónn 3 o copie el archivo en la carpeta Archivos encriptados\n");
		fflush(stdout);
		return(-1);
	} else if(i==1) {
		printf("-> Se ha encontrado 1 archivo disponible para desencriptar. Se usará el archivo %s por defecto\n", fileToDecrypt);
		fflush(stdout);
		sprintf(rutaToDecrypt, "./Archivos encriptados/%s", fileToDecrypt); //Guardamos el nombre del archivo en rutaToDecrypt
	}else {
		printf("\nPASO 1. Seleccione cuál de los siguientes archivos desea desencriptar:\n");
		fflush(stdout);
		dir = opendir ("./Archivos encriptados/");
		if (dir != NULL) {
			i=0;
			/* Nos va a mostrar los archivos .enc que haya dentro de la carpeta Archivos encriptados*/
		  	while ((ent = readdir (dir)) != NULL) {
				if((ptr=strstr(ent->d_name, ".enc"))!=NULL) { //Mostramos solo los archivos encriptados

					i++;
					printf ("  %d. %s\n", i, ent->d_name);
				}
			}
			closedir(dir);
		} else {
		  	/* Problemas al abrir el directorio */
		  	printf("Error al mostrar los archivos\n");
		  	return(-1);
		}
		do{
			valido=0;
			printf("Introduzca el número del archivo >> ");
			scanf("%s", &opcion);
			opcion_l = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l < 1 || opcion_l > i) {
				printf("Ops... tendrás que meter un número entre 1 y %d la próxima vez ;) Try again!\n", i);
				fflush(stdout);
				valido=1;
			}
		}while(valido==1);

		/*Guardamos el nombre del archivo correspondiente en rutaToDecrypt*/
		dir = opendir ("./Archivos encriptados/");
		i=0;
	 	while ((ent = readdir (dir)) != NULL) {
			if((ptr=strstr(ent->d_name, ".enc"))!=NULL) {
				i++;
				if(opcion_l==i ) {
					sprintf(rutaToDecrypt, "./Archivos encriptados/%s", ent->d_name);
					strcpy(fileToDecrypt, ent->d_name);
				}
			}
		}
		closedir(dir);
	}

	/*Leemos y desencriptamos la cabecera del archivo*/ 
	if((ptrEncrypted=fopen(rutaToDecrypt, "rb")) == NULL) {
		printf("Error al crear el archivo\n");
		fflush(stdout);
		return(-1);
	}

	status=fread(bytesRelleno, 1, 2, ptrEncrypted);		//Leo los dos primeros bytes que me indican el tamaño del relleno
	status=fread(bytesReaded, 1, 3, ptrEncrypted); 		//Leo los siguientes 3 bytes
	*(bytesReaded+3)='\0';
	cabecera1=cesarDecrypt(bytesReaded, 17, varlocal); 	//Desencripto esos bytes para saber que tipo de cifrado se us
	*(cabecera1+3)='\0';
	status=fread(bytesReaded, 1, 3, ptrEncrypted); 		//Leo los siguientes 3 bytes
	*(bytesReaded+3)='\0';
	cabecera2=cesarDecrypt(bytesReaded, 14, varlocal2); 	//Desencripto esos bytes para saber el modo de funcionamiento
	*(cabecera2+3)='\0';

	/*PASO 2. Seleccionar keyset*/
	dir = opendir ("./Claves y certificados/");
	if (dir != NULL) {
		i=0;
		/* Va a leer los archivos .p15 que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((strstr(ent->d_name, ".p15"))!=NULL) { 
				i++;
				strcpy(nombreKeyset, ent->d_name);
			}
		}
		closedir(dir);
	} else {
	  	/* Problemas al abrir el directorio */
	  	printf("Error al mostrar los archivos\n");
	  	return(-1);
	}

	if(i==0) {
		printf("Todavía no ha ejecutado la opción 1\n");
		fflush(stdout);
		return(-1);
	} else if(i==1) {
		sprintf(rutaKeyset, "./Claves y certificados/%s", nombreKeyset);
		printf("\n-> Se ha encontrado 1 archivo keyset. Se usará el archivo %s por defecto\n", nombreKeyset);
		fflush(stdout);
	} else {
		printf("\nPASO 2. Seleccione cuál de los siguientes archivos corresponde con su keyset: \n");
		fflush(stdout);	
		dir = opendir ("./Claves y certificados/");
		if (dir != NULL) {
			i=0;
			/* Nos va a mostrar los archivos .p15 que haya dentro de la carpeta Claves y cert.*/
		  	while ((ent = readdir (dir)) != NULL) {
				if((ptr=strstr(ent->d_name, ".p15"))!=NULL) { 
					i++;
					printf("  %d. %s\n", i, ent->d_name);
					strcpy(nombreKeyset, ent->d_name);
				}
			}
			closedir(dir);

			do{
				valido=0;
				printf("Introduzca el número del archivo >> ");
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
					if(opcion_l==i ) {
						sprintf(rutaKeyset, "./Claves y certificados/%s", ent->d_name);
					}
				}

			}
			closedir(dir);
		}
	}
	/* Comprobamos el algoritmo de cifrado que se ha utilizado*/ 
	if((ptr=strstr(cabecera1,"aes"))!=NULL) strcpy(busSim, ".aes");
	else if((ptr=strstr(cabecera1, "des"))!=NULL) strcpy(busSim, ".des");
	else {
		printf("Error al leer el archivo. Vuelva a ejecutar la opción 3.\n");
		fflush(stdout);
		return(-1);
	}

	/*PASO 3. Seleccionar clave simétrica*/
	dir = opendir ("./Claves y certificados/");
	if (dir != NULL) {
		i=0;
		/* Va a leer los archivos .aes o .des que haya dentro de la carpeta Claves y cert.*/
	  	while ((ent = readdir (dir)) != NULL) {
			if((strstr(ent->d_name, busSim))!=NULL) { 
				i++;
				strcpy(nombreSim, ent->d_name);
			}
		}
		closedir(dir);
	} else {
	  	/* Problemas al abrir el directorio */
	  	printf("Error al mostrar los archivos\n");
	  	return(-1);
	}

	if(i==0) {
		printf("Todavía no ha ejecutado la opción 2\n");
		fflush(stdout);
		return(-1);
	} else if(i==1) {
		sprintf(rutaSim, "./Claves y certificados/%s", nombreSim);
		printf("\n-> Se ha encontrado 1 clave simétrica adecuada. Se usará el archivo %s por defecto\n", nombreSim);
		fflush(stdout);
	} else {
		printf("\nPASO 3. Seleccione cuál de los siguientes archivos corresponde con su clave simétrica: \n");
		fflush(stdout);	
		dir = opendir ("./Claves y certificados/");
		if (dir != NULL) {
			i=0;
			/* Nos va a mostrar los archivos .aes o .des que haya dentro de la carpeta Claves y cert.*/
		  	while ((ent = readdir (dir)) != NULL) {
				if((ptr=strstr(ent->d_name, busSim))!=NULL) { 
					i++;
					printf("  %d. %s\n", i, ent->d_name);
					strcpy(nombreSim, ent->d_name);
				}
			}
			closedir(dir);

			do{
				valido=0;
				printf("Introduzca el número del archivo >> ");
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
				if((ptr=strstr(ent->d_name, busSim))!=NULL) {
					i++;
					if(opcion_l==i ) {
						sprintf(rutaSim, "./Claves y certificados/%s", ent->d_name);
					}
				}

			}
			closedir(dir);
		}
	}


	/*PASO 4. Password*/
	do {
		valido=0;
		printf("\nPASO 4. Introduzca la contraseña que se usó para encriptar >> ");
		scanf("%s", password);
		if((strlen(password))<2) {
			valido=1;
			printf("La contraseña ha de tener más de un caracter\n");
			fflush(stdout);
		}
	} while(valido==1);


	/*Creo contextos*/
	CRYPT_CONTEXT contextoDecrypt, contextoPrivado;
	/*Compruebo si se usó AES o DES*/
	if((ptr=strstr(cabecera1, "aes"))!=NULL) {
		if((status=cryptCreateContext(&contextoDecrypt, CRYPT_UNUSED, CRYPT_ALGO_AES))!=CRYPT_OK) {
			printf("Error al crear contexto. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		if((status=cryptSetAttributeString(contextoDecrypt, CRYPT_CTXINFO_IV, "1234567891123456", 16))!=CRYPT_OK) {
			printf("Error con el vector de inicialización. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
	} else if((ptr=strstr(cabecera1, "des"))!=NULL) {
		if((status=cryptCreateContext(&contextoDecrypt, CRYPT_UNUSED, CRYPT_ALGO_DES))!=CRYPT_OK) {
			printf("Error al crear contexto. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		if((status=cryptSetAttributeString(contextoDecrypt, CRYPT_CTXINFO_IV, "12345678", 8))!=CRYPT_OK) {
			printf("Error con el vector de inicialización. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
	} else {
		printf("Error al leer el archivo. Vuelva a ejecutar la opción 3.\n");
		fflush(stdout);
		return(-1);
	}
	//Modo de funcionamiento en cabecera
	if((ptr=strstr(cabecera2, "ecb"))!=NULL) {
		if((status=cryptSetAttribute(contextoDecrypt, CRYPT_CTXINFO_MODE, CRYPT_MODE_ECB))!=CRYPT_OK) {
			printf("Error al asignar modo de funcionamiento\n");
			fflush(stdout);
			return(-1);
		}
	} else if((ptr=strstr(cabecera2, "cbc"))!=NULL) {
		if((status=cryptSetAttribute(contextoDecrypt, CRYPT_CTXINFO_MODE, CRYPT_MODE_CBC))!=CRYPT_OK) {
			printf("Error al asignar modo de funcionamiento\n");
			fflush(stdout);
			return(-1);
		}
	} else {
		printf("Error al leer el archivo. Vuelva a ejecutar la opción 3.\n");
		fflush(stdout);
		return(-1);
	}
	/*Clave simétrica*/
	if((ptrSim=fopen(rutaSim, "rb"))==NULL) {
			printf("Eror al abrir el archivo de la clave simétrica\n");
			fflush(stdout);
			return(-1);
	}
	stat(rutaSim, &st);
	keySize=st.st_size;
	claveDecrypt=(char *)malloc(keySize);
	status=fread(claveDecrypt, 1, keySize, ptrSim);

	//Recuperamos la clave privada y la guardamos en el contextoPrivado ya que la necesitamos.
	CRYPT_KEYSET keyset;
	if((status=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, rutaKeyset, CRYPT_KEYOPT_READONLY))!=CRYPT_OK) {
		printf("Error al abrir keyset. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptCreateContext(&contextoPrivado, CRYPT_UNUSED, CRYPT_ALGO_RSA))!=CRYPT_OK) {
		printf("Error al crear contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptGetPrivateKey(keyset, &contextoPrivado, CRYPT_KEYID_NAME, "claveRSA", password))!=CRYPT_OK) {
		printf("Es muy posible que hayas metido mal la contraseña. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptImportKey(claveDecrypt, keySize, contextoPrivado,contextoDecrypt))!=CRYPT_OK) {
		printf("Error al importar clave. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	/*Calculamos el tamaño sin cabeceras*/
	stat(rutaToDecrypt, &st);
	tam=st.st_size;
	/*Dos bytes de la cabecera referente a los bytes de relleno, cabecera1 (tipo clave), cabecera2 (modo)*/
	tam=tam-2-strlen(cabecera1)-strlen(cabecera2);
	buffer=(char *)malloc(tam);
	status=fread(buffer, 1, tam, ptrEncrypted);
	if((status=cryptDecrypt(contextoDecrypt, buffer, tam))!=CRYPT_OK) {
		printf("Error al desencriptar. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	/*Creamos la carpeta si no estaba creada ya antes*/
	sprintf(directorio, "./Archivos desencriptados");
	if (status = lstat(directorio, &st) != 0) {
		if(status=mkdir(directorio, 0777) != 0) {
			printf("Error al crear el directorio\n");
			fflush(stdout);
			return(-1);
		}	
	}
	/*Volcamos la información a un archivo legible*/
	/*Primero quitamos el .enc de la extensión*/
	if((ptr=(strrchr(fileToDecrypt, '.')))!=NULL) { //Quitamos el .enc
		*ptr='\0';
	}
	/*A continuación calculamos la ruta del archivo desencriptado*/
	sprintf(rutaDecrypted, "./Archivos desencriptados/%s", fileToDecrypt);
	ptrDecrypted=fopen(rutaDecrypted, "wb");
	/*Calculamos el número de bytes de relleno (tipo int)*/
	tamRelleno_l=strtol(bytesRelleno, &endptr, 10);
	tamRelleno=(int)tamRelleno_l;
	/*Escribimos en el archivo SIN los bytes de relleno*/
	if((status=fwrite(buffer, 1, tam-tamRelleno, ptrDecrypted))!=tam-tamRelleno) {
		printf("Error en la escritura del archivo\n");
		fflush(stdout);
		return(-1);
	}
	

	/*Cerramos lo necesario*/
	fclose(ptrDecrypted);
	fclose(ptrSim);
	fclose(ptrEncrypted);
	if((status=cryptKeysetClose(keyset))!=CRYPT_OK) {
		printf("Error al cerrar el keyset. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptDestroyContext(contextoDecrypt))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptDestroyContext(contextoPrivado))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	return(0);

}
