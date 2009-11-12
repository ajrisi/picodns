/*
** picodns_types.h
** 
** Made by Adam
** Login   <adam@toxic.rh.rit.edu>
** 
** Started on  Fri Dec  5 23:06:53 2008 Adam
** Last update Fri Dec  5 23:06:53 2008 Adam
*/

#ifndef   	PICODNS_TYPES_H_
# define   	PICODNS_TYPES_H_

#include <glib.h>

enum {
  DNS_IPV4,
  DNS_IPV6
};

typedef struct dns_address_s dns_address;

struct dns_address_s {
  int type;
  gchar *address;
};

typedef struct dns_flags_s dns_flags;

enum dns_responce_e {
  DNS_QUERY = 0,
  DNS_RESPONCE
};

enum dns_opcode_e {
  //  DNS_QUERY = 0, //already defined to the right value in he
  //  previous enum
  DNS_QUERY_OC = 0, //placeholder
  DNS_IQUERY = 1,
  DNS_STATUS = 2,
  DNS_NOTIFY = 4,
  DNS_UPDATE = 5
};

enum dns_truncated_e {
  DNS_NOTTRUNCATED = 0,
  DNS_TRUNCATED = 1
};

enum dns_recursion_e {
  DNS_NORECURSION = 0,
  DNS_RECURSION
};

enum dns_auth_e {
  DNS_NONAUTH = 0,
  DNS_AUTH
};

enum dns_types_e {
  A = 1,
  AAAA = 28,
  AFSDB = 18,
  AXFR = 252,
  CERT = 37,
  CNAME = 5,
  DHCID = 49,
  DLV = 32769,
  DNAME = 39,
  DNSKEY = 48,
  DS = 43,
  HIP = 55,
  IPSECKEY = 45,
  IXFR = 251,
  KEY = 25,
  LOC = 29,
  MX = 15,
  NAPTR = 35,
  NS = 2,
  NSEC = 47,
  NSEC3PARAM = 51,
  OPT = 41,
  PTR = 12,
  RRSIG = 46,
  SIG = 24,
  SOA = 6,
  SPF = 99,
  SRV = 33,
  SSHFP = 44,
  TA = 32768,
  TKEY = 249,
  TSIG = 250,
  TXT = 16,
  DNS_TYPE_UNKNOWN
};

enum dns_classes_e {
  IN = 1,
  CS = 2,
  CH = 3,
  HS = 4,
  DNS_CLASS_UNKNOWN
};

enum dns_rr_type_e {
  DNS_QUESTION,
  DNS_ANSWER,
  DNS_AUTHORITY,
  DNS_ADDITIONAL
};

struct dns_flags_s {
  guint16 Responce;
  guint16 OpCode;
  guint16 Authoritative;
  guint16 Truncated;
  guint16 RecursionDesired;
  guint16 RecursionAvailable;
  guint16 Z;
  guint16 AnswerAuthenticated;
  guint16 NonAuthOK;
  guint16 ReplyCode;
};

typedef struct dns_name_s dns_name;

struct dns_name_s {
  gchar **namev;
  guint char_len;
};

typedef struct dns_rr_s dns_rr;

struct dns_rr_s {
  enum dns_rr_type_e rr_type;

  dns_name name;
  guint16 Type;
  guint16 Class;

  guint32 TTL;
  guint16 DataLength;

  //used in a and aaaa answer records
  dns_address addr;

  //used in mx answer records
  guint16 Preference;
  dns_name mail_exchange;

};

typedef struct dns_packet_s dns_packet;

struct dns_packet_s {
  guint16 TransactionID;
  dns_flags flags;
  guint16 QuestionRRCount;
  guint16 AnswerRRCount;
  guint16 AuthorityRRCount;
  guint16 AdditionalRRCount;

  GArray *QuestionRRs;
  GArray *AnswerRRs;
  GArray *AuthorityRRs;
  GArray *AdditionalRRs;

};

typedef struct dns_resolver_record_s dns_resolver_record;

struct dns_resolver_record_s {
  char *name;

  //requested flags
  gboolean request_authoratative;
  gboolean request_authenticated;
  
  //packet options
  gboolean ignore_non_auth_ok;

  dns_rr question;
  GArray *Answers;
};

typedef struct dns_lut_s dns_lut;

struct dns_lut_s {
  GHashTable *table;
};



#endif 	    /* !PICODNS_TYPES_H_ */
