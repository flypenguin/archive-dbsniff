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
#ifndef _littlehelpers_h
#define _littlehelpers_h 1

#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void fprint_hex_dump(FILE*, unsigned char*, int);
void print_hex_dump(unsigned char*, int);
char **parse_string(char *, int);
char **remove_doubles(char **);
int count_parsed_strings(char **);
int free_parsed_strings(char **);
char *get_timestr(time_t);

#ifdef __cplusplus
}
#endif


#endif
