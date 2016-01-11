#ifdef USE_DB

#include "db_defines.h"
#include "db.h"

#define ErrFile stderr

#include <assert.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>

// global variables.
// for the database ...
DB            *db               = NULL;
DBC           *dbc              = NULL;
DBT            dbkey, dbval;
db_key         key;
db_val         val;



void
setup_database(char *DBFile)
{
    int i;

    if ((i = db_create(&db, NULL, 0)) != 0)
    {
        fprintf(ErrFile, "error creating database.\n%s\n", db_strerror(i));
        _exit(-1);
    }
//#ifndef WIN32 // for some reason the win berkeley DOES NOT LIKE this ... :-/
//    if ((i=db_set_re_len(db, sizeof(db_val))) != 0)
//    {
//        fprintf(ErrFile, "error setting record length.\n%s\n", db_strerror(i));
//        _exit(-1);
//    }
//#endif
    if ((i = db_open(db, DBFile, DB_BTREE, DB_CREATE)) != 0)
    {
        fprintf(ErrFile, "error opening database.\n%s\n", db_strerror(i));
        _exit(-1);
    }
    memset(&dbkey, 0, sizeof(dbkey));          // initialize to zero
    memset(&dbval, 0, sizeof(dbval));
    dbkey.data = (void*)&key;                  // set all those things so
    dbkey.size = sizeof(db_key);               // we do not have to set them
    dbval.data = (void*)&val;                  // in the packet handler function
    dbval.size = sizeof(db_val);               // again every time :)
    assert(dbkey.data == &key);
}


char *
get_ipstr(u_int IP)
{
    static char IPstr[16];
    u_char *byte;

    byte = (u_char*)&IP;
    sprintf(IPstr, "%d.%d.%d.%d", byte[0], byte[1], byte[2], byte[3]);
    return IPstr;
}


#endif

