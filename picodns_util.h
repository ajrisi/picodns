/* picodns_util.h */

#include "picodns_types.h"

#include <glib.h>

#ifndef PICODNS_UTIL_H
#define PICODNS_UTIL_H

typedef struct buffer16_s buffer16;

struct buffer16_s {
  guint16 size;
  char *data;
};

typedef struct buffer8_s buffer8;

struct buffer8_s {
  guint8 size;
  char *data;
};


/* for debugging purposes, hexprint is used to print off the hex that is 
   pointed to by a void pointer. It prints "len" amount of data to the screen,
   followed by a new line */
void hexprint(void *buffer, int len);

/* converts the textual representation of an IPv4 address into the
   specialized DNS formatting */
GByteArray *ipv4_to_dns(const char *address);

/* converts the textual representation of an IPv6 address into the
   specialized DNS formatting */
GByteArray *ipv6_to_dns(const char *address);


dns_packet dns_packet_parse(GByteArray *data);
void dns_packet_print(dns_packet *packet);
GByteArray *dns_packet_pack(dns_packet *packet);
char *dns_type_to_ascii(int type);
char *dns_class_to_ascii(int class);
guint16 dns_flags_pack(dns_flags flags);
guint16 dns_type_from_ascii(char *type);
guint16 dns_class_from_ascii(char *class);
dns_name dns_name_make(char *string);
gchar *dns_name_to_ascii(dns_name name);
dns_address dns_address_unpack(int type, GByteArray *ba);
GByteArray *dns_rr_pack(dns_rr myrr);
dns_packet dns_packet_new(void);
dns_resolver_record *dns_resolver_record_new(void);

#endif
