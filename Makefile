CC     = gcc
CFLAGS = -Wall -Wextra -O2 -I. -Icrypto -Ivault -Isecurity -Ialerts -Iutils
LIBS   = -lssl -lcrypto -lm

SRCS   = main.c \
		 crypto/encrypt.c \
		 crypto/decrypt.c \
		 crypto/integrity.c \
		 crypto/kdf.c \
		 vault/vault.c \
		 security/lockout.c \
		 security/shredder.c \
		 alerts/discord.c \
		 utils/utils.c \
		 utils/audit.c
OBJS   = $(SRCS:.c=.o)
TARGET = bin/encrypt

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET).exe $(TARGET)