/* picodns_util.c */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <glib.h>
#include <string.h>
#include "picodns_util.h"
#include "picodns_types.h"

dns_flags dns_flags_parse(guint16 flags) {
  //get it into host byte order so all of the following operations
  //make sense
  
  dns_flags parsed_flags = {0};
  
  parsed_flags.Responce            = (flags & 0x8000) >> 15;
  parsed_flags.OpCode              = (flags & 0x7800) >> 11;
  parsed_flags.Authoritative       = (flags & 0x0400) >> 10;
  parsed_flags.Truncated           = (flags & 0x0200) >> 9;
  parsed_flags.RecursionDesired    = (flags & 0x0100) >> 8;
  parsed_flags.RecursionAvailable  = (flags & 0x0080) >> 7;
  parsed_flags.Z                   = (flags & 0x0040) >> 6;
  parsed_flags.AnswerAuthenticated = (flags & 0x0020) >> 5;
  parsed_flags.NonAuthOK           = (flags & 0x0010) >> 4;
  parsed_flags.ReplyCode           = (flags & 0x000F) >> 0;

  return parsed_flags;
};

guint16 dns_flags_make(enum dns_responce_e responce, enum dns_opcode_e opcode, enum dns_truncated_e truncated,
		   enum dns_recursion_e recursion, enum dns_auth_e auth) {
  guint16 dns_flags = 0;

  //unfortunately, enums are not guaranteed to be portable, so
  //switching is used here
  switch(responce) {
  case DNS_QUERY:
    dns_flags |= 0x0000;
    break;
  case DNS_RESPONCE:
    dns_flags |= 0x8000;
    break;
  }

  switch(opcode) {
  case  DNS_QUERY:
    dns_flags |= 0x0000;
    break;
  case DNS_IQUERY:
    dns_flags |= 0x0800;
    break;
  case DNS_STATUS:
    dns_flags |= 0x1000;
    break;
  case DNS_NOTIFY:
    dns_flags |= 0x2000;
    break;
  case DNS_UPDATE:
    dns_flags |= 0x2800;
    break;
  }

  switch(truncated) {
  case DNS_NOTTRUNCATED:
    dns_flags |= 0x0000;
    break;
  case DNS_TRUNCATED:
    dns_flags |= 0x0200;
    break;
  }

  switch(recursion) {
  case DNS_NORECURSION:
    dns_flags |= 0x0000;
    break;
  case DNS_RECURSION:
    dns_flags |= 0x0100;
    break;
  }

  //although we know that the Z bit is already set to 0, we explicitly
  //set it here as well
  dns_flags &= 0xFFBF;

  switch(auth) {
  case DNS_NONAUTH:
    dns_flags |= 0x0000;
    break;
  case DNS_AUTH:
    dns_flags |= 0x0010;
    break;
  }

  return GUINT16_TO_BE(dns_flags);
}

guint16 dns_flags_pack(dns_flags flags) {
  guint16 ret = 0;
  
  ret |= (flags.Responce            & 0x0001) << 15;
  ret |= (flags.OpCode              & 0x000F) << 11;
  ret |= (flags.Authoritative       & 0x0001) << 10;
  ret |= (flags.Truncated           & 0x0001) << 9;
  ret |= (flags.RecursionDesired    & 0x0001) << 8;
  ret |= (flags.RecursionAvailable  & 0x0001) << 7;
  ret |= (flags.Z                   & 0x0001) << 6;
  ret |= (flags.AnswerAuthenticated & 0x0001) << 5;
  ret |= (flags.NonAuthOK           & 0x0001) << 4;
  ret |= (flags.ReplyCode           & 0x000F) << 0;


  return ret;
}

dns_name dns_name_make(char *string) {
  dns_name ret = {0};
  ret.namev = g_strsplit_set(string, ".", 10);
  return ret;
}

void dns_name_free(dns_name name) {
  g_strfreev(name.namev);
}

gchar *dns_name_to_ascii(dns_name name) {
  return g_strjoinv(".", name.namev);
}

dns_name dns_name_parse(guint8 *string_begin) {
  dns_name ret = {0};
  //max of 10 strings
  ret.namev = calloc(11, sizeof(gchar*));
  /* process to parse a name is to read a byte, then read that many
     characters, and repeat  till a 0 is hit */
  guint8 index = 0;
  guint8 v_counter = 0;
  gsize num_to_read = (guint8)*(string_begin+index);
  while((num_to_read != 0) && (v_counter < 10)) {
    //read the given number of bytes into the string array */
    index++;
    ret.namev[v_counter] = g_strndup((gchar*)(string_begin+index), num_to_read);
    index += num_to_read;
    num_to_read = (guint8)*(string_begin+index);
    v_counter++;
  }
  ret.char_len = index+1;
  return ret;
}

GByteArray *dns_name_pack(dns_name name) {
  GByteArray *ret = g_byte_array_new();
  gchar **first = name.namev;
  if((*first == NULL) || (first == NULL)) {
    g_error("Can not pack name, there is nothing in the name vector!");
  }
  while((*first != NULL) && (first != NULL)) {
    guint8 length = strlen(*first);
    g_byte_array_append(ret, &length, 1);
    g_byte_array_append(ret, (guint8*)*first, length);
    first++;
  }
  guint8 zero = 0;
  g_byte_array_append(ret, &zero, 1); 
  return ret;
}

void dns_flags_print(dns_flags parsed_flags) {
  printf("Responce: %d\n", parsed_flags.Responce);
  printf("OpCode: %d\n", parsed_flags.OpCode);
  printf("Truncated: %d\n", parsed_flags.Truncated);
  printf("RecursionDesired: %d\n", parsed_flags.RecursionDesired);
  printf("Z: %d\n", parsed_flags.Z);
  printf("NonAuthOK: %d\n", parsed_flags.NonAuthOK);
}

GByteArray *dns_address_pack(dns_address address) {
  if (address.type == DNS_IPV4) {
    GByteArray *ret = g_byte_array_sized_new(4);
    
    struct in_addr *ptd = malloc(sizeof(struct in_addr));
    memset(ptd, 0, sizeof(struct in_addr));
    inet_pton(AF_INET, address.address, &(ptd->s_addr));
    
    g_byte_array_append(ret, (void*)&(ptd->s_addr), 4);

    return ret;
  } else if (address.type == DNS_IPV6) {
    GByteArray *ret = g_byte_array_sized_new(16);
    
    struct in6_addr *ptd = malloc(sizeof(struct in6_addr));
    memset(ptd, 0, sizeof(struct in6_addr));
    inet_pton(AF_INET6, address.address, &(ptd->s6_addr));
    
    g_byte_array_append(ret, (void*)&(ptd->s6_addr), 16);
    
    return ret;
    
  } else {
    return NULL;
  }
}

gchar *dns_address_to_ascii(dns_address address) {
  return address.address;
}

dns_address dns_address_unpack(int type, GByteArray *ba) {
  dns_address ret = {0};
  ret.type = type;

  if(type == DNS_IPV4) {
    gchar *addr = (gchar*)calloc(1, INET_ADDRSTRLEN+1);
    inet_ntop(AF_INET, ba->data, addr, INET_ADDRSTRLEN+1);
    ret.address = addr;
  } else if(type == DNS_IPV6) {
    gchar *addr = (gchar*)calloc(1, INET6_ADDRSTRLEN+1);
    inet_ntop(AF_INET6, ba->data, addr, INET6_ADDRSTRLEN+1);
    ret.address = addr;
  } else {
    g_error("unknown DNS address unpack type!");
  }

  return ret;
}

void hexprint(void *buffer, int len) {
  int i;
  for(i = 0; i < len; i++) {
    printf("%2.2x ", ((char*)buffer)[i]);
  }
  printf("\n");
  fflush(stdout);
}

void dns_packet_print(dns_packet *packet) {
  printf("New DNS Packet:\n");
  printf("  Transaction ID: %d\n", packet->TransactionID);
  printf("  Flags:\n");
  printf("    Responce: %d\n", packet->flags.Responce);
  printf("    OpCode: %d\n", packet->flags.OpCode);
  printf("    Truncated: %d\n", packet->flags.Truncated);
  printf("    RecursionDesired: %d\n", packet->flags.RecursionDesired);
  printf("    Z: %d\n", packet->flags.Z);
  printf("    NonAuthOK: %d\n", packet->flags.NonAuthOK);
  printf("  Questions: %d\n", packet->QuestionRRCount);
  printf("  Answer RRs: %d\n", packet->AnswerRRCount);
  printf("  Authority RRs: %d\n", packet->AuthorityRRCount);
  printf("  Additional RRs: %d\n", packet->AdditionalRRCount);

  if(packet->QuestionRRCount > 0) {
    printf("  Questions:\n");
    int index = 0;
    for(index = 0; index < packet->QuestionRRCount; index++) {
      dns_rr *myrr = &g_array_index(packet->QuestionRRs, dns_rr, index);
      dns_name myname = myrr->name;
      printf("    Question %d:\n", index);
      printf("      Name: %s\n", dns_name_to_ascii(myname));
      printf("      Type: %s\n", dns_type_to_ascii(g_array_index(packet->QuestionRRs, dns_rr, index).Type));
      printf("      Class: %s\n", dns_class_to_ascii(g_array_index(packet->QuestionRRs, dns_rr, index).Class));
    }
  }

  if(packet->AnswerRRCount > 0) {
    printf("  Answer RRs:\n");
    int index = 0;
    for(index = 0; index < packet->AnswerRRCount; index++) {
      printf("    Answer RR %d:\n", index);
    }
  }

  if(packet->AuthorityRRCount > 0) {
    printf("  Authority RRs:\n");
    int index = 0;
    for(index = 0; index < packet->AuthorityRRCount; index++) {
      printf("    Authority RR %d:\n", index);
    }
  }

  if(packet->AdditionalRRCount > 0) {
    printf("  Additional RRs:\n");
    int index = 0;
    for(index = 0; index < packet->AdditionalRRCount; index++) {
      printf("    Additional RR %d:\n", index);
    }
  }
  
  printf("\n");
}

GByteArray *dns_packet_pack(dns_packet *packet) {
  GByteArray *ret = g_byte_array_new();
  
  guint16 TransactionID = GUINT16_TO_BE(packet->TransactionID);
  g_byte_array_append(ret, (void*)&TransactionID, 2);

  guint16 Flags = dns_flags_pack(packet->flags);
  Flags = GUINT16_TO_BE(Flags);
  g_byte_array_append(ret, (void*)&Flags, 2);

  guint16 QuestionRRCount = packet->QuestionRRCount;
  QuestionRRCount = GUINT16_TO_BE(QuestionRRCount);
  g_byte_array_append(ret, (void*)&QuestionRRCount, 2);

  guint16 AnswerRRCount = packet->AnswerRRCount;
  AnswerRRCount = GUINT16_TO_BE(AnswerRRCount);
  g_byte_array_append(ret, (void*)&AnswerRRCount, 2);

  guint16 AuthorityRRCount = packet->AuthorityRRCount;
  AuthorityRRCount = GUINT16_TO_BE(AuthorityRRCount);
  g_byte_array_append(ret, (void*)&AuthorityRRCount, 2);

  guint16 AdditionalRRCount = packet->AdditionalRRCount;
  AdditionalRRCount = GUINT16_TO_BE(AdditionalRRCount);
  g_byte_array_append(ret, (void*)&AdditionalRRCount, 2);

  int i = 0;
  for(i = 0; i < packet->QuestionRRCount; i++) {
    g_debug("packing question %d", i);
    dns_rr question = g_array_index(packet->QuestionRRs, dns_rr, i);
    GByteArray *add = dns_rr_pack(question);
    g_byte_array_append(ret, add->data, add->len);
    g_byte_array_free(add, TRUE);
  }

  for(i = 0; i < packet->AnswerRRCount; i++) {
    GByteArray *add = dns_rr_pack(g_array_index(packet->AnswerRRs, dns_rr, i));
    g_byte_array_append(ret, add->data, add->len);
    g_byte_array_free(add, TRUE);
  }

  //more extension could go here
  

  return ret;
}

dns_packet dns_packet_new() {
  dns_packet ret = {0};
  ret.QuestionRRs = g_array_new(TRUE, TRUE, sizeof(dns_rr));
  ret.AnswerRRs = g_array_new(TRUE, TRUE, sizeof(dns_rr));
  ret.AuthorityRRs = g_array_new(TRUE, TRUE, sizeof(dns_rr));
  ret.AdditionalRRs = g_array_new(TRUE, TRUE, sizeof(dns_rr));
  return ret;
}

dns_packet dns_packet_parse(GByteArray *data) {
  dns_packet ret = {0};

  //make a copy into local memory
  GByteArray *copy = g_byte_array_sized_new(data->len);
  g_byte_array_append(copy, data->data, data->len);

  //pull the DNS transaction id off
  if(copy->len >= 2) {
    ret.TransactionID = *((guint16*)copy->data);
    ret.TransactionID = GUINT16_FROM_BE(ret.TransactionID);
  }
  g_byte_array_remove_range(copy, 0, 2);

  //pull the flags off
  if(copy->len >= 2) {
    guint16 flags = *((guint16*)copy->data);
    flags = GUINT16_FROM_BE(flags);
    ret.flags = dns_flags_parse(flags);
  }
  g_byte_array_remove_range(copy, 0, 2);

  //pull the question count off
  if(copy->len >= 2) {
    guint16 count = *((guint16*)copy->data);
    ret.QuestionRRCount = GUINT16_FROM_BE(count);
    ret.QuestionRRs = g_array_sized_new(TRUE, TRUE, sizeof(dns_rr), ret.QuestionRRCount);
  }
  g_byte_array_remove_range(copy, 0, 2);

  //pull the answer count off
  if(copy->len >= 2) {
    guint16 count = *((guint16*)copy->data);
    ret.AnswerRRCount = GUINT16_FROM_BE(count);
    ret.AnswerRRs = g_array_sized_new(TRUE, TRUE, sizeof(dns_rr), ret.AnswerRRCount);
  }
  g_byte_array_remove_range(copy, 0, 2);

  //pull the authority count off
  if(copy->len >= 2) {
    guint16 count = *((guint16*)copy->data);
    ret.AuthorityRRCount = GUINT16_FROM_BE(count);
    ret.AuthorityRRs = g_array_sized_new(TRUE, TRUE, sizeof(dns_rr), ret.AuthorityRRCount);
  }
  g_byte_array_remove_range(copy, 0, 2);

  //pull the additional count off
  if(copy->len >= 2) {
    guint16 count = *((guint16*)copy->data);
    ret.AdditionalRRCount = GUINT16_FROM_BE(count);
    ret.AdditionalRRs = g_array_sized_new(TRUE, TRUE, sizeof(dns_rr), ret.AdditionalRRCount);
  }
  g_byte_array_remove_range(copy, 0, 2);

  //now, parse apart the queries (this is based on the count of the
  //queries)
  int rr_count = 0;

  for(rr_count = 0; rr_count < ret.QuestionRRCount; rr_count++) {
    dns_rr myrr = {0};
    myrr.rr_type = DNS_QUESTION;

    dns_name parsed = dns_name_parse(copy->data);
    g_byte_array_remove_range(copy, 0, parsed.char_len);
    myrr.name = parsed;

    guint16 type = *((guint16*)copy->data);
    type = GUINT16_FROM_BE(type);
    g_byte_array_remove_range(copy, 0, 2);
    myrr.Type = type;

    guint16 class = *((guint16*)copy->data);
    class = GUINT16_FROM_BE(class);
    g_byte_array_remove_range(copy, 0, 2);
    myrr.Class = class;

    //add to array of question rrs
    g_array_append_val(ret.QuestionRRs, myrr);
  }

  for(rr_count = 0; rr_count < ret.AnswerRRCount; rr_count++) {
    dns_rr myrr = {0};
    myrr.rr_type = DNS_ANSWER;

    dns_name parsed = dns_name_parse(copy->data);
    g_byte_array_remove_range(copy, 0, parsed.char_len);
    myrr.name = parsed;

    guint16 type = *((guint16*)copy->data);
    type = GUINT16_FROM_BE(type);
    g_byte_array_remove_range(copy, 0, 2);
    myrr.Type = type;

    guint16 class = *((guint16*)copy->data);
    class = GUINT16_FROM_BE(class);
    g_byte_array_remove_range(copy, 0, 2);
    myrr.Class = class;

    guint32 TTL = *((guint32*)copy->data);
    TTL = GUINT32_FROM_BE(TTL);
    g_byte_array_remove_range(copy, 0, 4);
    myrr.TTL = TTL;

    guint16 DataLength = *((guint16*)copy->data);
    DataLength = GUINT16_FROM_BE(DataLength);
    g_byte_array_remove_range(copy, 0, 2);
    myrr.DataLength = DataLength;
    
    if(type == A) {
      dns_address addr = dns_address_unpack(DNS_IPV4, copy);
      myrr.addr = addr;
    } else if (type == AAAA) {
      dns_address addr = dns_address_unpack(DNS_IPV6, copy);
      myrr.addr = addr;
    } else if (type == MX) {
      g_warning("parsing of MX type packets not yet programmed!");
    } else if (type == PTR) {
      g_warning("parsing of PTR type packets not yet supported!");
    } else {
      //unknown type, can not process data
    }
    g_byte_array_remove_range(copy, 0, myrr.DataLength);

    //add to array of answer rrs
    g_array_append_val(ret.AnswerRRs, myrr);
  }

  for(rr_count = 0; rr_count < ret.AuthorityRRCount; rr_count++) {
  }

  for(rr_count = 0; rr_count < ret.AdditionalRRCount; rr_count++) {
  }
  
  //free the copy array
  g_byte_array_free(copy, TRUE);

  return ret;
}

char *dns_type_to_ascii(int type) {
  switch(type) {
  case  A: return "A";
  case  AAAA: return "AAAA";
  case AFSDB: return "AFSDB";
  case AXFR: return "AFXR";
  case CERT: return "CERT";
  case CNAME: return "CNAME";
  case DHCID: return "DHCID";
  case DLV: return "DLV";
  case DNAME: return "DNAME";
  case DNSKEY: return "DNSKEY";
  case DS: return "DS";
  case HIP: return "HIP";
  case IPSECKEY: return "IPSECKEY";
  case IXFR: return "IXFR";
  case KEY: return "KEY";
  case LOC: return "LOC";
  case MX: return "MX";
  case NAPTR: return "NAPTR";
  case NS: return "NS";
  case NSEC: return "NSEC";
  case NSEC3PARAM: return "NSEC3PARAM";
  case OPT: return "OPT";
  case PTR: return "PTR";
  case RRSIG: return "RRSIG";
  case SIG: return "SIG";
  case SOA: return "SOA";
  case SPF: return "SPF";
  case SRV: return "SRV";
  case SSHFP: return "SSHFP";
  case TA: return "TA";
  case TKEY: return "TKEY";
  case TSIG: return "TSIG";
  case TXT: return "TXT";
  default: return "UNKNOWN";
  }
  return "UNKNOWN";
}

guint16 dns_type_from_ascii(char *type) {
  if(strcmp(type, "A") == 0) { return A; }
  else if(strcmp(type, "AAAA") == 0) { return AAAA; }
  else if(strcmp(type, "AFSDB") == 0) { return AFSDB; }
  else if(strcmp(type, "AXFR") == 0) { return AXFR; }
  else if(strcmp(type, "CERT") == 0) { return CERT; }
  else if(strcmp(type, "CNAME") == 0) { return CNAME; }
  else if(strcmp(type, "DHCID") == 0) { return DHCID; }
  else if(strcmp(type, "DLV") == 0) { return DLV; }
  else if(strcmp(type, "DNAME") == 0) { return DNAME; }
  else if(strcmp(type, "DNSKEY") == 0) { return DNSKEY; }
  else if(strcmp(type, "DS") == 0) { return DS; }
  else if(strcmp(type, "HIP") == 0) { return HIP; }
  else if(strcmp(type, "IPSECKEY") == 0) { return IPSECKEY; }
  else if(strcmp(type, "IXFR") == 0) { return IXFR; }
  else if(strcmp(type, "KEY") == 0) { return KEY; }
  else if(strcmp(type, "LOC") == 0) { return LOC; }
  else if(strcmp(type, "MX") == 0) { return MX; }
  else if(strcmp(type, "NAPTR") == 0) { return NAPTR; }
  else if(strcmp(type, "NS") == 0) { return NS; }
  else if(strcmp(type, "NSEC") == 0) { return NSEC; }
  else if(strcmp(type, "NSEC3PARAM") == 0) { return NSEC3PARAM; }
  else if(strcmp(type, "OPT") == 0) { return OPT; }
  else if(strcmp(type, "PTR") == 0) { return PTR; }
  else if(strcmp(type, "RRSIG") == 0) { return RRSIG; }
  else if(strcmp(type, "SIG") == 0) { return SIG; }
  else if(strcmp(type, "SOA") == 0) { return SOA; }
  else if(strcmp(type, "SPF") == 0) { return SPF; }
  else if(strcmp(type, "SRV") == 0) { return SRV; }
  else if(strcmp(type, "SSHFP") == 0) { return SSHFP; }
  else if(strcmp(type, "TA") == 0) { return TA; }
  else if(strcmp(type, "TKEY") == 0) { return TKEY; }
  else if(strcmp(type, "TSIG") == 0) { return TSIG; }
  else if(strcmp(type, "TXT") == 0) { return TXT; }
  else { return DNS_TYPE_UNKNOWN; }
}

guint16 dns_class_from_ascii(char *class) {
  if(strcmp(class, "IN") == 0) { return IN; }
  else if (strcmp(class, "CS") == 0) { return CS; }
  else if (strcmp(class, "CH") == 0) { return CH; }
  else if (strcmp(class, "HS") == 0) { return HS; }
  else { return DNS_CLASS_UNKNOWN; }
}

char *dns_class_to_ascii(int class) {
  switch(class) {
  case IN: return "IN";
  case CS: return "CS";
  case CH: return "CH";
  case HS: return "HS";
  default: return "UNKNOWN";
  }
  return "UNKNOWN";
}

GByteArray *dns_rr_pack(dns_rr myrr) {
  //pack a dns_rr into its byte array
  GByteArray *ret = g_byte_array_new();

  switch(myrr.rr_type) {
  case DNS_QUESTION: {
    //format for this is the name, then the type, then the class
    
    //name
    GByteArray *name = dns_name_pack(myrr.name);
    g_byte_array_append(ret, name->data, name->len);
    g_byte_array_free(name, TRUE);

    //type
    guint16 type = GUINT16_TO_BE(myrr.Type);
    g_byte_array_append(ret, (guint8*)&type, 2);

    //class
    guint16 class = GUINT16_TO_BE(myrr.Class);
    g_byte_array_append(ret, (guint8*)&class, 2);

  } break; /* DNS_QUESTION */

  case DNS_ANSWER: {
    //format for this is name, type, class, ttl, datalength, address
    
    //name
    GByteArray *name = dns_name_pack(myrr.name);
    g_byte_array_append(ret, name->data, name->len);
    g_byte_array_free(name, TRUE);

    //type
    guint16 type = GUINT16_TO_BE(myrr.Type);
    g_byte_array_append(ret, (guint8*)&type, 2);

    //class
    guint16 class = GUINT16_TO_BE(myrr.Class);
    g_byte_array_append(ret, (guint8*)&class, 2);

    //TTL
    guint32 TTL = GUINT32_TO_BE(myrr.TTL);
    g_byte_array_append(ret, (guint8*)&TTL, 4);

    //datalength
    guint16 DataLength = GUINT16_TO_BE(myrr.DataLength);
    g_byte_array_append(ret, (guint8*)&DataLength, 2);

    //here, switch on the type of the answer packet
    switch(myrr.Type) {
    case A:
    case AAAA: {
      
      //address
      GByteArray *addr = dns_address_pack(myrr.addr);
      g_byte_array_append(ret, addr->data, addr->len);
    } break; /* cases A and AAAA */
    case MX: {
      //preference
      guint16 pref = GUINT16_TO_BE(myrr.Preference);
      g_byte_array_append(ret, (guint8*)&pref, 2);

      //exchange
      GByteArray *ex_name = dns_name_pack(myrr.mail_exchange);
      g_byte_array_append(ret, ex_name->data, ex_name->len);

    } break; /* type MX */
    case PTR: {
      //host name
      GByteArray *host = dns_name_pack(myrr.name);
      g_byte_array_append(ret, host->data, host->len);
    } break;
    default:
      g_warning("Can not pack answer packet of type %s", dns_type_to_ascii(myrr.Type));
      return NULL;
    }

  } break; /* DNS_ANSWER */
  case DNS_AUTHORITY:
    break;
  case DNS_ADDITIONAL:
    break;
  default:
    return NULL;
  }
  return ret;
}

dns_resolver_record *dns_resolver_record_new() {
  dns_resolver_record *ret = g_slice_alloc0(sizeof(dns_resolver_record));
  ret->Answers = g_array_new(TRUE, TRUE, sizeof(dns_rr));
  return ret;
}
