/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Función que genera y distribuye de forma segura una clave pública.
 * Plataforma:     Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.35
 * Fecha:          14-10-10
 * =========================================================================================
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "cryptlib.h"


int funcion1()
{
	int status, certLength, certMaxLength, valido;
	void *cert; 
	char *dirClaves, *nombreKeyset, *nombreCert, *rutaCert, *rutaKeyset, *password, *ptr;
	FILE *ptrCert;
	struct stat datos;
	
	/*Reservo memoria*/	
	dirClaves=(char *)malloc(50);
	rutaKeyset=(char *)malloc(100);
	nombreKeyset=(char *)malloc(50);
	rutaCert=(char *)malloc(100);
	nombreCert=(char *)malloc(50);
	password=(char *)malloc(50);

	system("clear");
	printf("\n ------------------------------------\n");
	printf("|        Generar clave pública       |\n");
	printf(" ------------------------------------\n\n");
	fflush(stdout);

	/*PASO 1. Nombre keyset*/
	printf("PASO 1. Teclee el nombre que quiere dar al archivo keyset: ");
	fflush(stdout);
	scanf("%s", nombreKeyset);
	if((ptr=strstr(nombreKeyset, ".p15"))==NULL) {
		sprintf(rutaKeyset, "./Claves y certificados/%s.p15", nombreKeyset); //No ha puesto extensión
	} else sprintf(rutaKeyset, "./Claves y certificados/%s", nombreKeyset); //Puso extensión

	/*PASO 2. Nombre certificado*/
	printf("\nPASO 2. Teclee el nombre que quiere dar al archivo certificado: ");
	fflush(stdout);
	scanf("%s", nombreCert);
	if((ptr=strstr(nombreCert, ".cert"))==NULL) {
		sprintf(rutaCert, "./Claves y certificados/%s.cert", nombreCert); //No ha puesto extensión
	} else sprintf(rutaCert, "./Claves y certificados/%s", nombreCert); //Puso extensión
	
	/*PASO 3. Password*/	
	do{
		valido=0;
		printf("\nPASO 3. Teclee la contraseña que desee usar: ");
		fflush(stdout);
		scanf("%s", password);
		if(strlen(password)<2) {
			printf("Introduzca una contraseña de más de un caracter\n");
			fflush(stdout);
			valido=1;
		}
	}while(valido==1);
		
	/*Creamos el contexto y generamos un par de claves con GenerateKey*/	
	CRYPT_CONTEXT contextoRSA;
	if((status=cryptCreateContext(&contextoRSA, CRYPT_UNUSED, CRYPT_ALGO_RSA))!=CRYPT_OK) { //Hasta aquí tenemos la 'caja' creada de RSA
		printf("Error al crear el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptSetAttributeString(contextoRSA, CRYPT_CTXINFO_LABEL, "claveRSA", 8))!=CRYPT_OK) {
		printf("Error al añadir atributos. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptGenerateKey(contextoRSA))!=CRYPT_OK) { //Crea una clave y la deja en ese contexto
		printf("Error al generar la clave. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}	

	/*Guardamos la clave pública y privada*/
	/*Primero guardamos la clave pública en un certificado*/
	CRYPT_CERTIFICATE certificado;
	if((status=cryptCreateCert(&certificado, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE))!=CRYPT_OK) {
		printf("Error al crear el certificdo. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptSetAttribute(certificado, CRYPT_CERTINFO_XYZZY, 1))!=CRYPT_OK) { //Con este atributo hacemos que la creacion sea 'simple'
		printf("Error añadir atributos al certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptSetAttribute(certificado, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, contextoRSA))!=CRYPT_OK) {
		printf("Error al añadir atributos al certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptSetAttributeString(certificado, CRYPT_CERTINFO_COMMONNAME, "CertificadoRSA", 14))!=CRYPT_OK) {
		printf("Error al añadir atributos al certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	/*Firmo el certificado con la clave privada (huella digital)*/
	if((status=cryptSignCert(certificado, contextoRSA))!=CRYPT_OK) {
		printf("Error al firmar el certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	/*Ya tenemos el certificado creado y se quiere guardar*/
	if((status=cryptExportCert(NULL, 0, &certMaxLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, certificado))!=CRYPT_OK) {
		printf("Error al exportar el certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	cert=(char *)malloc(certMaxLength);
	if((status=cryptExportCert(cert, certMaxLength, &certLength, CRYPT_CERTFORMAT_TEXT_CERTIFICATE, certificado))!=CRYPT_OK) {
		printf("Error al exportar el certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	/*Vamos a guardar el certificado en un archivo*/
	/*Compruebo que exista el directorio. Si lstat devuelve 0 es que existe. Si devuelve otro valor hay que crear el directorio*/
	sprintf(dirClaves, "./Claves y certificados");
	if (status = lstat(dirClaves, &datos) != 0) {
		if(status=mkdir(dirClaves, 0777) != 0) {
			printf("Error al crear el dirClaves\n");
			fflush(stdout);
			return(-1);
		}
	}
	if((ptrCert=fopen(rutaCert, "wb")) < 0) {
		printf("Error al crear el archivo\n");
		fflush(stdout);
		return(-1);
	}
	if((status=fwrite(cert, 1, certLength, ptrCert))!=certLength) {
		printf("Error al guardar el certificado\n");
		fflush(stdout);
		return(-1);
	}

	/*Guardamos la clave privada en un objeto de tipo keyset*/
	CRYPT_KEYSET keyset;
	if((status=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, rutaKeyset, CRYPT_KEYOPT_CREATE))!=CRYPT_OK) {
		printf("Error al abrir el keyset. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptAddPrivateKey(keyset, contextoRSA, password))!=CRYPT_OK) {
		printf("Error al añadir contraseña. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}


	/*Cerramos descriptores de archivos y destruimos lo necesario*/
	fclose(ptrCert);
	if((status=cryptKeysetClose(keyset))!=CRYPT_OK) {
		printf("Error al cerrar el keyset. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptDestroyCert(certificado))!=CRYPT_OK) {
		printf("Error al destruir el certificado. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}
	if((status=cryptDestroyContext(contextoRSA))!=CRYPT_OK) {
		printf("Error al destruir el contexto. Código %d\n", status);
		fflush(stdout);
		return(-1);
	}

	return(0);

}
