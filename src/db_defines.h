#ifdef USE_DB

/*
 * if you enable USE_DB please make sure to inlcude libdb42sd.lib to the 
 * linker input libs. (or a similar db version, of course)
 */

#ifndef __dbdefines_h
#define __dbdefines_h

#include "db.h"

#include "extsniff.h"

#define db_open(db, file, type, flags) \
    db->open(db, NULL, file, NULL, type, flags, 0)
#define db_get(db, key, data) \
    db->get(db, NULL, key, data, 0)
#define db_put(db, key, data) \
    db->put(db, NULL, key, data, 0)
#define db_close(db) \
    db->close(db, 0)
#define db_set_re_len(db, len) \
    db->set_re_len(db, len)
#define db_cursor(db, dbc) \
    db->cursor(db, NULL, dbc, 0)
#define dbc_get(cursor, key, data, flags) \
    cursor->c_get(cursor, key, data, flags)


#ifdef __cplusplus
extern "C" {
#endif

extern DB            *db;
extern DBT            dbkey, dbval;
extern DBC           *dbc;
extern db_key         key;
extern db_val         val;

void        setup_database(char *);
char*       get_ipstr(u_int);

#ifdef __cplusplus
}
#endif


#endif

#endif