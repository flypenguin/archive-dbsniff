#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "getopt.h"

void
print_help()
{
    fprintf(stdout, "\nprints the system time in various ways.\n");
    fprintf(stdout, "the following modes are valid: \n");
    fprintf(stdout, "\t-f (format string)\n");
    fprintf(stdout, "\t\tprints the time formatted like in format string\n");
    fprintf(stdout, "\t-t (UNIX time)\n");
    fprintf(stdout, "\t\tprints the given (UNIX time) instead of the system time\n");
    fprintf(stdout, "\t-u   prints the UNIX time (seconds since 1.1.1970)\n");
    fprintf(stdout, "\t-n   don't print carriage return after time\n");
    fprintf(stdout, "the format string modifiers are as follows:\n");
    fprintf(stdout, "\t%%a Abbreviated weekday name\n");
    fprintf(stdout, "\t%%A Full weekday name\n");
    fprintf(stdout, "\t%%b Abbreviated month name \n");
    fprintf(stdout, "\t%%B Full month name \n");
    fprintf(stdout, "\t%%c Date and time representation appropriate for locale \n");
    fprintf(stdout, "\t%%d Day of month as decimal number (01 - 31) \n");
    fprintf(stdout, "\t%%H Hour in 24-hour format (00 - 23) \n");
    fprintf(stdout, "\t%%I Hour in 12-hour format (01 - 12) \n");
    fprintf(stdout, "\t%%j Day of year as decimal number (001 - 366) \n");
    fprintf(stdout, "\t%%m Month as decimal number (01 - 12) \n");
    fprintf(stdout, "\t%%M Minute as decimal number (00 - 59) \n");
    fprintf(stdout, "\t%%p Current locale's A.M./P.M. indicator for 12-hour clock \n");
    fprintf(stdout, "\t%%S Second as decimal number (00 - 59) \n");
    fprintf(stdout, "\t%%U Week of year (00-53) as decimal number, Sunday 1st day of week\n");
    fprintf(stdout, "\t%%w Weekday as decimal number (0 - 6; Sunday is 0) \n");
    fprintf(stdout, "\t%%W Week of year (00-53) as decimal number, Monday 1st day of week\n");
    fprintf(stdout, "\t%%x Date representation for current locale \n");
    fprintf(stdout, "\t%%X Time representation for current locale \n");
    fprintf(stdout, "\t%%y Year without century, as decimal number (00 - 99) \n");
    fprintf(stdout, "\t%%Y Year with century, as decimal number \n");
    fprintf(stdout, "\t%%z, %%Z Either the time-zone name or time zone abbreviation, \n");
    fprintf(stdout, "\t    depending on registry settings; \n");
    fprintf(stdout, "\t   no characters if time zone is unknown \n");
    fprintf(stdout, "\t%%%% Percent sign \n");
    fprintf(stdout, "\n");
}


int   no_crlf;
int   time_to_print;
char *format_string;


void
print_unix_time()
{
    fprintf(stdout, "%lu", time(NULL));
    if (no_crlf == 0)
        fprintf(stdout, "\n");
}

print_formated_time(char *format_string)
{
    struct tm *time_now;
    time_t time_now_secs;
    char buffer[1000];
    if (time_to_print == -1) time_now_secs = time(NULL);
	else time_now_secs = time_to_print;
    time_now = localtime(&time_now_secs);
    strftime(buffer, sizeof(buffer), format_string, time_now);
    fprintf(stdout, buffer);
    if (no_crlf == 0)
        fprintf(stdout, "\n");
}


int 
main(int argc, char **argv)
{
    int c;
    int time_mode; 
    char *format_string;

    no_crlf = 0;
    time_mode = 0;
	time_to_print = -1;
	format_string = NULL;
	time_mode = 2;

	while ((c=getopt(argc, argv, "uhf:nt:")) != -1)
    {
        switch (c)
        {
        case 'u':
            time_mode = 1;
            break;
        case 'h':
            print_help();
            break;
        case 'f':
            format_string = strdup(optarg);
            time_mode = 2;
            break;
        case 'n':
            no_crlf = 1;
            break;
        case 't':
            time_to_print = strtol(optarg, 0, 10);
            break;
        default:
            print_help();
            break;
        }
    }

	if (format_string == NULL) format_string = "%b %d %Y, %Xh";

    if (time_mode == 1)
        print_unix_time();
    else if (time_mode == 2)
        print_formated_time(format_string);
    else
        print_help();

    return 0;
}