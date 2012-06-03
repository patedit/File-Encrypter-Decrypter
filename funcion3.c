/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Permite encriptar un archivo usando algún tipo de cifrado. Pediremos al
 *                 usuario el cifrado a usar, tamaño de bloque, tamaño clave...
 * Plataforma:     Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.35
 * Fecha:          21-10-10
 * =========================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "cryptlib.h"

extern char* cesarEncrypt(char cadena[], int pos, char cabecera1[]);

int funcion3()
{
	int tam, tam2, tamRelleno, status, keySize, valido, i, tamCert, keyMaxSize;
	long int opcion_l2, opcion_l;
	char opcion[5], *claveEncrypt, *buffer, *ptr, *endptr, *rutaToEncrypt, *directorio, *rutaSim, *nombreSim, *rutaEncrypted, *cabecera1, *cabecera2, *varlocal, *varlocal2, *password, *rutaKeyset, *nombreKeyset, *busSim, *bytesRelleno, *bufferCert, *claveExportada;
	FILE *ptrEncrypt, *ptrSim, *ptrEncrypted, *ptrCert;	
	DIR *dir;
	struct stat st;
	struct dirent *ent;

	CRYPT_CERTIFICATE certificado;
	/*Reservo memoria*/
	nombreKeyset=(char *)malloc(50);
	rutaKeyset=(char *)malloc(120);
	password=(char *)malloc(20);
	rutaToEncrypt=(char *)malloc(120);
	directorio=(char *)malloc(120);
	rutaSim=(char *)malloc(120);
	busSim=(char *)malloc(5);
	nombreSim=(char *)malloc(50);
	rutaEncrypted=(char *)malloc(120);
	varlocal=(char *)malloc(3);
	varlocal2=(char *)malloc(3);
	cabecera1=(char *)malloc(3);
	cabecera2=(char *)malloc(3);
	bytesRelleno=(char *)malloc(2);

	system("clear");
	printf("\n ------------------------------------\n");
	printf("|          Cifrar un archivo          |\n");
	printf(" ------------------------------------\n\n");
	fflush(stdout);
	/*PASO 1. Ruta del archivo a cifrar*/
	do {
		valido=0;
		printf("PASO 1. Introduzca la ruta del archivo que desea cifrar: ");
		scanf("%s", rutaToEncrypt);
		if((ptrEncrypt=fopen(rutaToEncrypt, "rb")) == NULL ) {
			printf("No se encuentra el archivo. Revise la ruta :)\n\n");
			valido=1;
			fflush(stdout);
		} 
	} while(valido==1);

	/*Buscamos el caracter '/' dentro de la cadena. Si está, es porque el usuario metió la ruta completa*/
	if((ptr=(strrchr(rutaToEncrypt, '/')))!=NULL) sprintf(rutaEncrypted, "./Archivos encriptados/%s.enc", ptr+1); //Ruta completa
	else sprintf(rutaEncrypted, "./Archivos encriptados/%s.enc", rutaToEncrypt); //El usuario metió el nombre del archivo

	/*PASO 2. Algoritmo de cifrado*/
	do {
		valido=0;
		printf("\nPASO 2. Seleccione el algoritmo de cifrado que desea utilizar:\n");
		printf("  1. AES (por defecto)\n");
		printf("  2. DES\n");
		printf("  3. RSA\n");
		fflush(stdout);
		printf("Opción (Introduzca 0 para la opción por defecto) >> ");	
	
		scanf ("%s", &opcion);

		/*Comprobacion de la validez de la selección (que sea un número)
		(usando strtol, si hay algun caracter no numérico, endptr apunta al primero de ellos,
		lo cual implica que si la cadena apuntada por endptr no tiene longitud 0
		es porque se ha introducido un caracter no numérico)*/
		opcion_l = strtol(opcion,&endptr,10);

		if(strlen(endptr)!=0 || opcion_l < 0 || opcion_l > 3) {
			printf("Ops... tendrás que meter un número entre 1 y 3 la próxima vez ;) Try again!\n");
			fflush(stdout);
			valido=1;
		}
	} while(valido==1);

	/*Distinto tratamiento según el cifrado escogido*/
	CRYPT_CONTEXT contextoEncrypt, contextoPrivado;
	if(opcion_l==1 || opcion_l==0) { //AES
		/*Vamos a comprobar que tam sea multiplo del tamaño de bloque*/
		stat(rutaToEncrypt, &st);
		tam2=st.st_size;
		if(tam2%16!=0)	{
			tam=(int)tam2/16;
			tam++;
			tam=tam*16;	
			tamRelleno=tam-tam2; 
		}
		else {
			tamRelleno=0;
			tam=tam2;
		}

		/*Creamos contextos..*/
		if((status=cryptCreateContext(&contextoEncrypt, CRYPT_UNUSED, CRYPT_ALGO_AES))!=CRYPT_OK) {
			printf("Error al crear el contexto AES. Código %d\n", status);
			fflush(stdout);
			return(-1);
		} else if((status=cryptSetAttributeString(contextoEncrypt, CRYPT_CTXINFO_IV, "1234567891123456", 16))!=CRYPT_OK) {
			printf("Error con el vector de inicialización. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		do { //Seleccionamos el tamaño de clave en AES
			valido=0;
			printf("\nPASO 3. Seleccione el tamaño de clave:\n");
			printf("  1. 128 bits (por defecto)\n");
			printf("  2. 192 bits\n");
			printf("  3. 256 bits\n");
			fflush(stdout);
			printf("Opción (Introduzca 0 para la opción por defecto)>> ");	
			scanf ("%s", &opcion);
			/*Comprobacion de la validez de la selección (que sea un número)
			(usando strtol, si hay algun caracter no numérico, endptr apunta al primero de ellos,
			lo cual implica que si la cadena apuntada por endptr no tiene longitud 0
			es porque se ha introducido un caracter no numérico)*/
			opcion_l2 = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l2 < 0 || opcion_l2 > 3) {
				printf("Ops... tendrás que meter un número entre 1 y 3 la próxima vez ;) Try again!\n");
				fflush(stdout);
				valido=1;
			}
		} while(valido==1);
		if(opcion_l2==2) {
			if((status=cryptSetAttribute(contextoEncrypt, CRYPT_CTXINFO_KEYSIZE, 192/8))!=CRYPT_OK) { //192 bits
				printf("Error al asignar tamaño de clave. Código %d\n", status);
				fflush(stdout);
				return(-1);
			}
		} else if(opcion_l2==3) {
			if((status=cryptSetAttribute(contextoEncrypt, CRYPT_CTXINFO_KEYSIZE, 256/8))!=CRYPT_OK) { //256 bits
				printf("Error al asignar tamaño de clave. Código %d\n", status);
				fflush(stdout);
				return(-1);
			}
		}
		strcpy(busSim, ".aes");
		/*Será la cabecera que incluiremos al principio del archivo encriptado*/
		cabecera1=cesarEncrypt("aes", 17, varlocal);/*Ciframos "aes" con cifrado césar. Número de posiciones desplazadas: 17 */
	} else if(opcion_l==2) { //DES
		/*Vamos a comprobar que tam sea multiplo del tamaño de bloque*/
		stat(rutaToEncrypt, &st);
		tam2=st.st_size;
		if(tam2%16!=0)	{
			tam=(int)tam2/16;
			tam++;
			tam=tam*16;	
			tamRelleno=tam-tam2; 
		}
		else {
			tamRelleno=0;
			tam=tam2;
		}

		if((status=cryptCreateContext(&contextoEncrypt, CRYPT_UNUSED, CRYPT_ALGO_DES))!=CRYPT_OK) {
			printf("Error al crear el contexto DES. Código %d\n", status);
			fflush(stdout);
			return(-1);
		} else if((status=cryptSetAttributeString(contextoEncrypt, CRYPT_CTXINFO_IV, "12345678", 8))!=CRYPT_OK) {
			printf("Error con el vector de inicialización. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		strcpy(busSim, ".des");

		/*Será la cabecera que incluiremos al principio del ptrEncrypt encriptado*/
		cabecera1=cesarEncrypt("des", 17, varlocal);/*Ciframos "des" con cifrado césar. Número de posiciones desplazadas: 17 */
	} else if(opcion_l==3) { //RSA
		stat(rutaToEncrypt, &st);
		tam2=st.st_size;
		if(tam2%128!=0)	{
			tam=(int)tam2/128;
			tam++;
			tam=tam*128;	 
		}
		else {
			tam=tam2;
		}

	}
	if(opcion_l==0 || opcion_l==1) printf("\nPASO 4. Seleccione el modo de funcionamiento:\n");
	if(opcion_l==2) printf("\nPASO 3. Seleccione el modo de funcionamiento:\n");
	
	/*Modo de funcionamiento si se seleccionó cifrado simétrico*/
	if(opcion_l!=3) {
		do {
			valido=0;
			printf("  1. CBC (por defecto)\n");
			printf("  2. ECB\n");
			fflush(stdout);
			printf("Opción (Introduzca 0 para la opción por defecto) >> ");	
			scanf ("%s", &opcion);
			/*Comprobacion de la validez de la selección (que sea un número)
			(usando strtol, si hay algun caracter no numérico, endptr apunta al primero de ellos,
			lo cual implica que si la cadena apuntada por endptr no tiene longitud 0
			es porque se ha introducido un caracter no numérico)*/
			opcion_l2 = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l2 < 0 || opcion_l2 > 2) {
				printf("Ops... tendrás que meter un número entre 1 y 2 la próxima vez ;) Try again!\n");
				fflush(stdout);
				valido=1;
				}
		} while(valido==1);
		if(opcion_l2==1) { //CBC
			if((status=cryptSetAttribute(contextoEncrypt, CRYPT_CTXINFO_MODE, CRYPT_MODE_CBC))!=CRYPT_OK) {
				printf("Error al asignar modo de funcionamiento\n");
				fflush(stdout);
				return(-1);
			}
			cabecera2=cesarEncrypt("cbc", 14, varlocal2); /*Ciframos "cbc" con cifrado césar. Número de posiciones desplazadas: 14 */
		} else if(opcion_l2==2) { //ECB
			if((status=cryptSetAttribute(contextoEncrypt, CRYPT_CTXINFO_MODE, CRYPT_MODE_ECB))!=CRYPT_OK) {
				printf("Error al asignar modo de funcionamiento\n");
				fflush(stdout);
				return(-1);
			}
			cabecera2=cesarEncrypt("ecb", 14, varlocal2); /*Ciframos "ecb" con cifrado césar. Número de posiciones desplazadas: 14 */
		}
		/*Password*/
		if(opcion_l==1 || opcion_l==0) printf("\nPASO 5. Introduzca una contraseña >> "); 	
		if(opcion_l==2)	printf("\nPASO 4. Introduzca una contraseña >> "); 
		fflush(stdout);
	
		do {
			valido=0;
			scanf("%s", password);
			if((strlen(password))<2) {
				printf("La contraseña debe tener más de un caracter\n");
				fflush(stdout);
				valido=1;
			}
				
		}while(valido==1);
	

		/*Necesitamos la clave simétrica adecuada*/
		dir = opendir ("./Claves y certificados/");
		if (dir != NULL) {
			i=0;
			/* Nos va a mostrar los archivos que haya dentro de la carpeta Claves y cert. que correspondan*/
			while ((ent = readdir (dir)) != NULL) {
				if((ptr=strstr(ent->d_name, busSim))!=NULL) { 
					strcpy(nombreSim, ent->d_name);
					i++;
				}
			}
			closedir(dir);
		} else {
			/* Problemas al abrir el directorio */
			printf("¿Ha ejecutado ya la opción 2?\n");
			fflush(stdout);
			return(-1);
		}
		if(i==0) {
			printf("No se ha encontrado ninguna clave simétrica. (¿Ha ejecutado ya la opción 2?)\n");
			fflush(stdout);
			return(-1);
		} else if(i==1) {
			printf("\n-> Se ha encontrado 1 clave simétrica. Se usará %s por defecto\n\n", nombreSim);
			fflush(stdout);
			sprintf(rutaSim, "./Claves y certificados/%s", nombreSim);
		} else {
			printf("\n¡¡ Hay %d claves simétricas creadas !!\n", i);
			fflush(stdout);
			i=0;
			dir = opendir ("./Claves y certificados/");	
			/* Nos va a mostrar los archivos que haya dentro de la carpeta Claves y cert. adecuados*/
			while ((ent = readdir (dir)) != NULL) {
				if((ptr=strstr(ent->d_name, busSim))!=NULL) {
					i++; 
					printf("  %d. %s\n", i, ent->d_name);
				}
			}
			closedir(dir);
		
			do{
				valido=0;
				printf("Introduzca el número de la clave simétrica que desea usar >> ");
				scanf("%s", &opcion);
				opcion_l2 = strtol(opcion,&endptr,10);
				if(strlen(endptr)!=0 || opcion_l2 < 1 || opcion_l2 > i) {
					printf("Ops... tendrás que meter un número entre 1 y %d la próxima vez ;) Try again!\n", i);
					fflush(stdout);
					valido=1;
				}
			}while(valido==1);
	
			/*Guardamos el nombre del archivo correspondiente en rutaSim*/
			dir = opendir ("./Claves y certificados/");
			i=0;
			while ((ent = readdir (dir)) != NULL) {
				if((ptr=strstr(ent->d_name, busSim))!=NULL) {
					i++;
					if(opcion_l2==i) { 
						sprintf(rutaSim, "./Claves y certificados/%s", ent->d_name);
					}	
				}
			}
			closedir(dir);
		}
		/*Recuperamos la clave privada y la guardamos en el contextoPrivado ya que la necesitamos*/
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
				opcion_l2 = strtol(opcion,&endptr,10);
				if(strlen(endptr)!=0 || opcion_l2 < 1 || opcion_l2 > i) {
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
					if(opcion_l2==i) { 
						sprintf(rutaKeyset, "./Claves y certificados/%s", ent->d_name);
					}	
				}
			}
			closedir(dir);
		}
	
		/*Abrimos la clave simétrica elejida anteriormente por el usuario*/
		if((ptrSim=fopen(rutaSim, "rb")) == NULL) {
			printf("Error al abrir la clave simétrica. (¿La ha creado ya?)\n");
			fflush(stdout);
			return(-1);
		}
		stat(rutaSim, &st);
		keySize=st.st_size;
		claveEncrypt=(char *)malloc(keySize);
		status=fread(claveEncrypt, 1, keySize, ptrSim);
	
		/*Abrimos keyset, creamos contextos, importamos claves...*/
		CRYPT_KEYSET keyset;
		if((status=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, rutaKeyset, CRYPT_KEYOPT_READONLY))!=CRYPT_OK) {
			printf("Error al abrir el archivo keyset. (¿Ha ejecutado la opción 1?). Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		if((status=cryptCreateContext(&contextoPrivado, CRYPT_UNUSED, CRYPT_ALGO_RSA))!=CRYPT_OK) {
			printf("Error al crear el contexto. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		if((status=cryptGetPrivateKey(keyset, &contextoPrivado, CRYPT_KEYID_NAME, "claveRSA", password))!=CRYPT_OK) {
			printf("Error con la clave privada. (¿Es la misma contraseña que usó en la opción 1?). Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		if((status=cryptImportKey(claveEncrypt, keySize, contextoPrivado, contextoEncrypt))!=CRYPT_OK) {
			printf("Error al importar la clave. Asegúrese de que se usa el mismo algoritmo. Código %d\n", status);
			fflush(stdout);
			return(-1);
		}
		/*Encriptamos*/
		buffer=(char *)malloc(tam);
		status=fread(buffer, 1, tam, ptrEncrypt);
		if((status=cryptEncrypt(contextoEncrypt, buffer, tam))!=CRYPT_OK) {
			printf("Error al encriptar %s. CÃ³digo %d\n", rutaToEncrypt, status);
			fflush(stdout);
			return(-1);
		}
	}

	if(opcion_l==3) {

		if((ptrCert=fopen("./Claves y certificados/AES.cert", "rb")) == NULL ) {
			printf("Compruebe que haya generado ya una clave pública\n");
			fflush(stdout);
			return(-1);
		}
		stat("./Claves y certificados/AES.cert", &st);
		tamCert=st.st_size;
		bufferCert=(char *)malloc(tamCert);
		status=fread(bufferCert, 1, tamCert, ptrCert);

		if((status=cryptImportCert(bufferCert, tamCert, CRYPT_UNUSED, &certificado))!=CRYPT_OK) {
			printf("Error al importar el certificado. Código %d\n", status);
			fflush(stdout);
			return(-1);	
		}

		/*Encriptamos de 128 bytes en 128 bytes. Sin embargo, no podemos hacer cryptEncrypt para el mismo certificado/contexto. Pero lo 
dejamos asi ya que nos dara el error -21 esperado en la primera iteracion*/
		tam2=tam/128;
		buffer=(char *)malloc(tam);
		for(i=0; i<tam2; i++) {
			status=fread(buffer, 1, 128, ptrEncrypt);
			if((status=cryptEncrypt(certificado, buffer, 128))!=CRYPT_OK) {	
				printf("Error al cifrar el archivo %s. Código %d\n", rutaToEncrypt, status);
				fflush(stdout);
				return(-1);
			}
			*ptrEncrypt=*(ptrEncrypt+128);
			*buffer=*(buffer+128);
		}
	}

	/*Guardamos el archivo encriptado.*/
	/*Compruebo que exista el directorio. Si lstat devuelve 0 es que existe. Si devuelve otro valor hay que crear el directorio*/
	sprintf(directorio, "./Archivos encriptados");
	if (status = lstat(directorio, &st) != 0) {
		if(status=mkdir(directorio, 0777) != 0) {
			printf("Error al crear el directorio\n");
			fflush(stdout);
			return(-1);
		}	
	}

	/*La ruta la hemos calculado al principio del todo, cuando el usuario metio la ruta del archivo*/
	if((ptrEncrypted=fopen(rutaEncrypted, "wb")) == NULL) {
		printf("Error al crear el archivo\n");
		fflush(stdout);
		return(-1);
	}
	
	/*Vamos a incluir una cabecera en el archivo para saber después los bytes de relleno que hemos añadido*/
	sprintf(bytesRelleno, "%d", tamRelleno);
	if((status=fwrite(bytesRelleno, 1, 2, ptrEncrypted))!=2) {
		printf("Error al guardar el archivo\n");
		fflush(stdout);
		return(-1);
	}

	/*Vamos a incluir una cabecera en el archivo para saber despues que tipo de cifrado se uso*/
	*(cabecera1+3)='\0'; //Nos aseguramos que solo sean 3 bytes
	if((status=fwrite(cabecera1, 1, strlen(cabecera1), ptrEncrypted))!=strlen(cabecera1)) {
		printf("Error al guardar el archivo\n");
		fflush(stdout);
		return(-1);
	}
	/*Vamos a incluir una cabecera en el archivo para saber después el modo de funcionamiento que se uso*/
	*(cabecera2+3)='\0'; //Nos aseguramos que solo sean 3 bytes
	if((status=fwrite(cabecera2, 1, strlen(cabecera2), ptrEncrypted))!=strlen(cabecera2)) {
		printf("Error al guardar el archivo\n");
		fflush(stdout);
		return(-1);
	}
	/*Guardamos los bytes del archivo encriptado en un archivo*/
	if((status=fwrite(buffer, 1, tam, ptrEncrypted))!=tam) {
		printf("Error al guardar el archivo\n");
		fflush(stdout);
		return(-1);
	}

	/*Cerramos descriptores y destruimos lo que sea necesario*/
	fclose(ptrEncrypted);
	fclose(ptrSim);
	fclose(ptrEncrypt);
	//if((status=cryptKeysetClose(keyset))!=CRYPT_OK) {
	//	printf("Error al cerrar el keyset. Código %d\n", status);
	//	fflush(stdout);
	//	return(-1);
	//}

	if((status=cryptDestroyContext(contextoPrivado))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	if((status=cryptDestroyContext(contextoEncrypt))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	return(0);

}
