/* ************************************************************************** *
   This file is part of extsniff.

   extsniff is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   extsniff is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with extsniff; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * ************************************************************************** */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int count_parsed_strings(char **string)
{
   int i;

   i = 0;
   while (string[i])
   {
	 i++;
   }
   return i;
}



int free_parsed_strings(char **string)
{
   int i = 0;
   while(string[i]){
      free(string[i]);
      i++;
   }
   // don't forget the NULL pointer at the end! :-)
   free(string[i]);
   free(string);   

   return 0;
}


char **parse_string(char *string, int length)
{
   
   int found, max_elements, begin, inside, part_length, pos;
   char **temp, **bigger, **returnme;
   
   begin        = 0;
   found        = 0;
   max_elements = 9;
   inside       = 0;
   returnme     = (char**)calloc(10, sizeof(char*));

   if (length == -1) 
      length = (int) strlen(string);

   pos = 0;
   while ( pos < length && string[pos] != 0)
   {
	 if ((string[pos] >= 'a' && string[pos] <= 'z') || 
	     (string[pos] >= 'A' && string[pos] <= 'Z') || 
	     (string[pos] >= '0' && string[pos] <= '9') ||  
	     (string[pos] == '!' || string[pos] == '-'))
	 {
	       if (!inside)
	       {
		     inside = 1;
		     begin = pos;
	       }
	 }
	 else
	 {
	       if (inside)
	       {
		     if (found == max_elements)
		     {
			   max_elements += 5;
			   bigger = (char**)calloc(max_elements + 1, sizeof(char*));
			   memcpy(bigger, returnme, (max_elements - 5)*sizeof(char*));
			   temp = returnme;
			   returnme = bigger; 
			   free(temp);
		     }
		     inside = 0;
		     part_length = pos - begin;
		     returnme[found] = (char*)calloc(part_length + 1, 1); 
		     memcpy(returnme[found], (string+begin), part_length);
		     found++;
	       }
	 }
	 pos++;
   }

   if (inside)
   {
	 if (found == max_elements)
	 {
	       max_elements += 5;
	       bigger = (char**)calloc(max_elements + 1, sizeof(char*));
	       memcpy(bigger, returnme, found*sizeof(char*));
	       temp = returnme;
	       returnme = bigger;
	       free(temp);
	 }
	 inside = 0;
	 part_length = pos - begin;
	 returnme[found] = (char*)calloc(part_length + 1, 1); 
	 memcpy(returnme[found], (string+begin), part_length);
	 found++;
   }
   

   
   return returnme;
}



char **remove_doubles(char **words)
{

   int num_words;
   int i, n;

   num_words = count_parsed_strings(words);

   n = 0;
   while (words[n])
   {
	 for (i = n+1; i < num_words; i++)
	 {
	       if (strcmp(words[n], words[i]) == 0)
	       {
		     free(words[i]);
		     words[i] = words[num_words - 1];
		     num_words--;
		     i--;
		     words[num_words] = NULL;
	       }
	 }
	 n++;
   }

   return words;
}


void 
fprint_hex_dump(FILE *where, unsigned char* buffer, int length)
{
    int i,j,k;
    k = length - length % 16;
    k = length / 16;
    for (j=0; j<k; j++)
       {
	  for (i=0; i<=15; i++)
	  {
	     printf("%.2x ", *(buffer+j*16+i));
	     if (i==7)
		printf(" ");
	  }
	  printf("\n");
       }
    
    j *= 16;

    for (i=j; i<length; i++)
       {
	  printf("%.2x ", *(buffer+i));
	  if ( i-j == 7 )
	     printf(" ");

       }
    
    printf("\n");

}

void 
print_hex_dump(unsigned char* buffer, int length)
{
    fprint_hex_dump(stdout, buffer, length);
}


//inline
char *
get_timestr(time_t the_time)
{
    static char timestr[100];
    if (!the_time) the_time = time(NULL);
    //return ctime(&the_time);
    strftime(timestr, sizeof(timestr), "%a %d.%m.%Y %H:%M:%S", localtime(&the_time));
    return timestr;
}


