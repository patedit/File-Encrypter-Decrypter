/*
 * =========================================================================================
 * Autor:          Lara Revilla y Sergio Alonso (rscx31)
 * Compilacion:    make
 * Uso:            ./main
 * Funcion:        Aplicaci�n de seguridad que muestra un men� para que el usuario seleccione
 *		   la opci�n que desee haciendo uso de la librer�a cryptlib.
 * 		   Creaci�n de claves sim�tricas, asim�tricas, cifrado de informaci�n, firmas...
 * Plataforma:     Compilado y probado en Linux 2.6.26 y 2.6.32
 * Fecha:          14-10-10
 * =========================================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cryptlib.h"


int main()
{
	int status, valido, salir;
	char opcion[5];
	long int opcion_l;
	char *endptr;
	

	status=cryptInit(); // Inicializa la librer�a. Todas las funciones de cryptlib devuelven un entero.
	if(status!=CRYPT_OK) {
		//Ha habido un error 
		//Si status=0, la operaci�n se ha realizado con �xito. Si no, dar� el c�digo de error correspondiente (-1, -2..)
		//Los c�digos de error est�n en cryptlib.h 
		printf("\nError al inicializar la librer�a. C�digo %d.\n", status);
		fflush(stdout);
		return -1;
	}

	salir=0;
	do {
		system("clear");
		status=cryptAddRandom(NULL, CRYPT_RANDOM_SLOWPOLL); //Recopila datos aleatorios a partir de eventos aleatorios (como el movimiento del rat�n) para generar claves distintas y aleatorias.
		if(status!=CRYPT_OK) {
			printf("\nError al recopilar datos aleatorios. C�digo %d.\n", status);
			fflush(stdout);
			return -1;
		}


		printf("\n ------------------------------------\n");
		printf("|     Aplicaci�n de seguridad v1.0   |\n");
		printf(" ------------------------------------\n\n");
		fflush(stdout);
		printf("  1. Generar y distribuir de forma segura una clave p�blica. \n");
		printf("  2. Generar e intercambiar de forma segura entre dos usuarios una clave sim�trica. \n");
		printf("  3. Cifrar un archivo de cualquier tama�o y formato. \n");
		printf("  4. Descifrar informaci�n. \n");
		printf("  5. Firmar digitalmente un archivo. \n");
		printf("  6. Verificar una firma digital. \n");
		printf("\n");
		printf("  0. Salir. \n");

		do{
			printf("\nElija la opci�n que desee >> ");
			scanf ("%s", &opcion);
			valido=0;
			/*Comprobacion de la validez de la selecci�n (que sea un n�mero)
			(usando strtol, si hay algun caracter no num�rico, endptr apunta al primero de ellos,
			lo cual implica que si la cadena apuntada por endptr no tiene longitud 0
			es porque se ha introducido un caracter no num�rico)*/
			opcion_l = strtol(opcion,&endptr,10);
			if(strlen(endptr)!=0 || opcion_l < 0 || opcion_l > 6) {
				printf("Ops... tendr�s que meter un n�mero entre 0 y 6 la pr�xima vez ;) Try again!\n");
				fflush(stdout);
				valido=1;
			}
		} while(valido==1);

		switch (opcion_l){
			case 0:
				if((status=cryptEnd())!=CRYPT_OK) {; //Finaliza la librer�a
					printf("Saliendo... :(\n");
					fflush(stdout);
					printf("\nError al cerrar la librer�a. C�digo %d.\n", status);
					fflush(stdout);
					return -1;
				}
				salir=1;
				printf("Saliendo... :)\n");
				break;
			case 1:
				if((status=funcion1())==0) {
					printf("\n�Clave p�blica generada con �xito! \nPuedes encontrar los archivos en la carpeta Claves y certificados");
					printf("\n\n[RETURN para continuar o CONTROL+C para salir] .....");
					getchar();
					getchar();
				} else salir=1;
				break;

			case 2:
				if((status=funcion2())==0) {
					printf("\n�Clave sim�trica generada con �xito!\nPuedes encontrarla en la carpeta Claves y certificados");
					printf("\n\n[RETURN para continuar o CONTROL+C para salir] .....");
					getchar();
					getchar();
				} else salir=1;
				break;
			case 3:
				if((status=funcion3())==0) {
					printf("\n�Archivo encriptado con �xito!\nPuedes encontrarlo en la carpeta Archivos encriptados\n");
					printf("\n\n[RETURN para continuar o CONTROL+C para salir] .....");
					getchar();
					getchar();
				} else salir=1;
				break;
			case 4:
				if((status=funcion4())==0) {
					printf("\n�Archivo desencriptado con �xito!\nPuedes encontrarlo en la carpeta Archivos desencriptados\n");
					printf("\n\n[RETURN para continuar o CONTROL+C para salir] .....");
					getchar();
					getchar();
				} else salir=1;
				break;
			case 5:
				if((status=funcion5())==0) {
					printf("\n�Archivo firmado digitalmente con �xito!\nPuedes encontrar la firma en la carpeta Firmas digitales\n");
					printf("\n\n[RETURN para continuar o CONTROL+C para salir] .....");
					getchar();
					getchar();
				} else salir=1;
				break;
			case 6:
				if((status=funcion6())==0) {
					printf("\n�La firma digital concuerda con el archivo!\n");
					printf("\n\n[RETURN para continuar o CONTROL+C para salir] .....");
					getchar();
					getchar();
				} else salir=1;
				break;
		}
	}while(salir==0);

	return 0;

}

