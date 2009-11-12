##
## Makefile
##  
## Made by Adam
## Login   <adamtoxic.rh.rit.edu>
##
## Started on  Mon Nov  3 20:28:00 2008 Adam
## Last update Mon Nov  3 20:28:00 2008 Adam
## 
##############################
# Complete this to make it ! #
##############################
NAME 	=picodns		# Name of executable file
SRC	= picodns_util.c picodns_config.c picodns_resolver.c picodns.c	# List of *.c
INCL  	=picodns_resolver.h picodns_config.h picodns_util.h picodns_types.h picodns.h		# List of *.h
################
# Optional add #
################
IPATH   = -I. `pkg-config --cflags glib-2.0`
OBJOPT  = -O2 -ggdb -Wall -Wstrict-prototypes  
EXEOPT  = -O2 -ggdb -Wall -Wstrict-prototypes  `pkg-config --libs glib-2.0` -lconfuse
LPATH   = -L. 

#####################
# Macro Definitions #
#####################
CC 	= cc
MAKE 	= make
SHELL	= /bin/sh
OBJS 	= $(SRC:.c=.o) 
RM 	= /bin/rm -f 	
COMP	= gzip -9v
UNCOMP	= gzip -df
STRIP	= strip

CFLAGS  = $(OBJOPT) $(IPATH)
LDFLAGS = $(EXEOPT) $(LPATH)

.SUFFIXES: .h.Z .c.Z .h.gz .c.gz .c.z .h.z 

##############################
# Basic Compile Instructions #
##############################

all:	$(NAME)
$(NAME): $(OBJS) $(SRC) $(INCL)  
	$(CC) $(OBJS) $(LDFLAGS) -o $(NAME) 
#	$(STRIP) ./$(NAME) # if you debug ,don't strip ...

depend:
	gcc $(IPATH) -MM $(SRC) 
clean:
	-$(RM) $(NAME) $(OBJS) *~
fclean:
	-$(RM) $(NAME)
comp: clean
	$(COMP) $(INCL) $(SRC)
ucomp: 
	$(UNCOMP) $(SRC) $(INCL)

.c.Z.c .h.Z.h .c.gz.c .h.gz.h .c.z.c .h.z.h :
	 -$(UNCOMP) $<

.c.o:
	$(CC) $(CFLAGS) -c $< 
################
# Dependencies #
################
