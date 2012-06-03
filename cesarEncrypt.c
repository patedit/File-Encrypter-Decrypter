/*
 * =========================================================================================
 * Autor: 	Lara Revilla y Sergio Alonso (rscx31)
 * Uso: 	Función externa del programa de seguridad. Se usa en la funcion3.c
 * Funcion:	Codifica una cadena usando el cifrado cesar.
 * Plataforma:	Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.35
 * Fecha:	14-10-10
 * =========================================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* cesarEncrypt(char cadena[],int pos, char codigocesar[])
{

	int i,j,longitud_cad,dif;
	char abecedario[26];
	char encriptada[200];
	sprintf(abecedario, "abcdefghijklmnopqrstuvwxyz");

	
	longitud_cad=strlen(cadena);
	for (i=0; i<longitud_cad; i++) 
	{
		for(j=0; j<=25; j++) 
		{
			if (cadena[i]==abecedario[j])
			{
				if(26-j<=pos) 
				{
					dif=pos-(26-j);
					codigocesar[i]=abecedario[dif];	

				} else {
				codigocesar[i]=abecedario[j+pos];
				}
			}
	
		}
	}

	return(codigocesar);

}

