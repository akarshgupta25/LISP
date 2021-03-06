############################################################################
#  Filename: Makefile
#
#  Description: This file is used to compile the packet generator 
#              
############################################################################

BASE_DIR=$(PWD)
CC=gcc
CFLAGS=-Wall

INCLUDE_DIR=$(BASE_DIR)/include
OBJ_DIR=$(BASE_DIR)/obj
SRC_DIR=$(BASE_DIR)/src
BIN_DIR=$(BASE_DIR)/bin

CFLAGS+=-I$(INCLUDE_DIR)
DEPS= \
    $(INCLUDE_DIR)/lisp_hdrs.h \
    $(INCLUDE_DIR)/lisp_defn.h \
    $(INCLUDE_DIR)/lisp_tdfs.h
    
OBJ_FILES=$(OBJ_DIR)/lisp_main.o \
          $(OBJ_DIR)/lisp_util.o \
          $(OBJ_DIR)/lisp_itr.o \
          $(OBJ_DIR)/lisp_etr.o

EXE_NAME=xTR
LD=-lpthread

EXE_NAME_MSMR=MSMR
OBJ_FILES_MSMR=$(OBJ_DIR)/lisp_msmr.o

exe: $(OBJ_FILES) $(OBJ_FILES_MSMR)
	@$(CC) $(CFLAGS) -o $(BIN_DIR)/$(EXE_NAME) $(OBJ_FILES) $(LD)
	@$(CC) $(CFLAGS) -o $(BIN_DIR)/$(EXE_NAME_MSMR) $(OBJ_FILES_MSMR) $(LD)

xtr: $(OBJ_FILES)
	@$(CC) $(CFLAGS) -o $(BIN_DIR)/$(EXE_NAME) $(OBJ_FILES) $(LD)

msmr: $(OBJ_FILES_MSMR)
	@$(CC) $(CFLAGS) -o $(BIN_DIR)/$(EXE_NAME_MSMR) $(OBJ_FILES_MSMR) $(LD)

$(OBJ_DIR)/lisp_main.o: $(SRC_DIR)/lisp_main.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/lisp_main.o $(SRC_DIR)/lisp_main.c $(INCLUDES)

$(OBJ_DIR)/lisp_util.o: $(SRC_DIR)/lisp_util.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/lisp_util.o $(SRC_DIR)/lisp_util.c $(INCLUDES)

$(OBJ_DIR)/lisp_itr.o: $(SRC_DIR)/lisp_itr.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/lisp_itr.o $(SRC_DIR)/lisp_itr.c $(INCLUDES)

$(OBJ_DIR)/lisp_etr.o: $(SRC_DIR)/lisp_etr.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/lisp_etr.o $(SRC_DIR)/lisp_etr.c $(INCLUDES)

$(OBJ_DIR)/lisp_msmr.o: $(SRC_DIR)/lisp_msmr.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/lisp_msmr.o $(SRC_DIR)/lisp_msmr.c $(INCLUDES)

clean:
	@rm -rf $(OBJ_DIR)/*.o
	@rm -rf $(BIN_DIR)/$(EXE_NAME)
	@rm -rf $(BIN_DIR)/$(EXE_NAME_MSMR)
