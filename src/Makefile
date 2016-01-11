# Source, Executable, Includes, Library Defines
INCL   = littlehelpers.h extsniff.h db_defines.h confnet.h pack_decode.h params.h ph1line.h tp_base.h tp_ext.h disponly.h linwrap.h mode_sum.h
SRC    = littlehelpers.c db_defines.c  
SRC_S  = extsniff.c confnet.c params.c tp_base.c tp_ext.c ph1line.c pack_decode.c disponly.c mode_sum.c
SRC_D  = extdump.c

OBJ    = $(SRC:.c=.o)
OBJ_S  = $(SRC_S:.c=.o)
OBJ_D  = $(SRC_D:.c=.o)
LIBS_S = -ldb -lpcap
LIBS_D = -ldb
OBJ_N  = $(SRC_N:.c=.o)

# nwait and npush
SRC_N  = winwrap.c 
SRC_NW = nwait.c
SRC_NP = npush.c
OBJ_NW = $(SRC_NW:.c=.o)
OBJ_NP = $(SRC_NP:.c=.o)
EXE_NW = nwait
EXE_NP = npush

# loss_chk and loss_srv
SRC_LS = loss_srv.c 
SRC_LC = loss_chk.c
OBJ_LS = $(SRC_LS:.c=.o)
OBJ_LC = $(SRC_LC:.c=.o)
EXE_LC = loss_chk
EXE_LS = loss_srv

# make all stuff :-)
EXE_S  = extsniff
EXE_D  = extdump

all:	$(EXE_S) $(EXE_NW) $(EXE_NP) $(EXE_LS) $(EXE_LC)

# Compiler, Linker Defines
CC      = /usr/bin/gcc
CFLAGS  = -Wall -O2 -funroll-loops
#CFLAGS  = -pedantic -Wall -g -DDEBUG $(LDFLAGS)  # DEBUG CFLAGS, change if you want to debug :-)
LIBPATH = -L.
RM      = /bin/rm -f

# Compile and Assemble C Source Files into Object Files
all:	$(MKALL)
%.o: %.c 
	$(CC) -c $(CFLAGS) $*.c

# Link all Object Files with external Libraries into Binaries
$(EXE_S): $(OBJ) $(OBJ_S)
	$(CC) $(LIBPATH) $(OBJ) $(OBJ_S) $(LIBS_S) -o $(EXE_S)

$(EXE_D): $(OBJ) $(OBJ_D)
	$(CC) $(LIBPATH) $(OBJ) $(OBJ_D) $(LIBS_D) -o $(EXE_D)

$(EXE_NW): $(OBJ_N) $(OBJ_NW)
	$(CC) $(LIBPATH) $(OBJ_N) $(OBJ_NW) -o $(EXE_NW)

$(EXE_NP): $(OBJ_N) $(OBJ_NP)
	$(CC) $(LIBPATH) $(OBJ_N) $(OBJ_NP) -o $(EXE_NP)

$(EXE_LS): $(OBJ_LS) 
	$(CC) $(LIBPATH) $(OBJ_LS) -o $(EXE_LS)

$(EXE_LC): $(OBJ_LC) 
	$(CC) $(LIBPATH) $(OBJ_LC) -o $(EXE_LC)

static:	$(OBJ)

# Objects depend on these Libraries
$(OBJ): $(INCL)

# Create a gdb/dbx Capable Executable with DEBUG flags turned on
debug:
	$(CC) $(CFDEBUG) $(SRC)

# Clean Up Objects, Exectuables, Dumps out of source directory
clean:
	$(RM) *.o $(EXE_D) $(EXE_S) $(EXE_LS) $(EXE_LC) $(EXE_NW) $(EXE_NP)    

