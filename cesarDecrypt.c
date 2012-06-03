/* ===========================================================================
 * Autor:	Lara Revilla y Sergio Alonso (rscx31)
 * Uso:		Funci√on externa al programa de seguridad. Se usa en lfuncion4.c
 * Funcion:	Decodifica una cadena previamente cifrada con codigo cesar.
 * Plataforma:	Compilado y probado en Linux 2.6.26, 2.6.32 y 2.6.35
 * Fecha:	15-10-10
 * ===========================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* cesarDecrypt(char cadena[],int pos, char codigocesar[])
{
	int i,j,longitud_cad,dif;
	char abecedario[26];
	sprintf(abecedario, "abcdefghijklmnopqrstuvwxyz");

	longitud_cad=strlen(cadena);


	for (i=0; i<=longitud_cad; i++) 
	{
		for(j=0; j<=25; j++) 
		{
			if (cadena[i]==abecedario[j])
			{
				if(j+1<=pos) 
				{
					dif=25-(pos-(j+1));
					codigocesar[i]=abecedario[dif];
						

				} else {
					codigocesar[i]=abecedario[j-pos];
				}
			}
	
		}
	}

	return(codigocesar);


}
