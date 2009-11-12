/*
** picodns_resolver.c
** 
** Made by (Adam)
** Login   <adam@toxic.rh.rit.edu>
** 
** Started on  Fri Dec 12 16:27:39 2008 Adam
** Last update Sun May 12 01:17:25 2002 Speed Blue
*/

#include "picodns_types.h"
#include "picodns_util.h"
#include "picodns_resolver.h"

#include <glib.h>
#include <confuse.h>
#include <stdlib.h>
#include <string.h>

dns_lut dns_lut_new(char *filepath) {
  dns_lut ret = {0};
  ret.table = g_hash_table_new(g_str_hash, g_str_equal); 

  cfg_t *cfg;
  int parse_result = 0;
  cfg = cfg_init(opts, CFGF_NOCASE);
  parse_result = cfg_parse(cfg, filepath);

  //printf("parsed: %d\n", parse_result);

  if(parse_result == CFG_FILE_ERROR) {
    g_warning("Could not load dns lookup table file \"%s\":\n  ", filepath);
    perror(filepath);
    return ret;
  } else if(parse_result == CFG_PARSE_ERROR) {
    g_warning("Parse error in DNS lookup table file \"%s\"\n", filepath);
    return ret;
  }
  
  int i;
  int num_a = cfg_size(cfg, "a_record");
  int num_aaaa = cfg_size(cfg, "aaaa_record");
  int num_mx = cfg_size(cfg, "mx_record");
  
///////////////////////////////////////////////////////////////////////
  for(i = 0; i < num_a; i++) {
    cfg_t *record = cfg_getnsec(cfg, "a_record", i);
    //create a record in memory
    dns_resolver_record *new_record = dns_resolver_record_new();
    //set the record name
    new_record->name = g_strdup(cfg_title(record));

    /* check for any requested flags for this record */
    new_record->request_authenticated = (cfg_getbool(record, "authenticated"))?TRUE:FALSE;
    new_record->request_authoratative = (cfg_getbool(record, "authoratative"))?TRUE:FALSE;
    new_record->ignore_non_auth_ok = (cfg_getbool(record, "ignore_authentication"))?TRUE:FALSE;

    /* now, put together the question. */
    dns_rr *question = &(new_record->question);
    question->rr_type = DNS_QUESTION;
    question->Type = A;
    question->Class = dns_class_from_ascii(cfg_getstr(record, "class"));
    question->name = dns_name_make(cfg_getstr(record, "host"));

    /* now, loop over each answer present, and make them and add
       themto the record */
    int num_answers = cfg_size(record, "answer");
    int j = 0;
    for(j=0; j < num_answers; j++) {
      cfg_t *answer = cfg_getnsec(record, "answer", j);
      dns_rr temp_answer = {0};
      temp_answer.rr_type = DNS_ANSWER;
      temp_answer.Type = A;
      temp_answer.Class = question->Class;
      temp_answer.name = dns_name_make(cfg_getstr(record, "host"));
      temp_answer.DataLength = 4;
      temp_answer.TTL = cfg_getint(answer, "TTL");
      temp_answer.addr.type = DNS_IPV4;
      temp_answer.addr.address = g_strdup(cfg_getstr(answer, "addr"));
      g_array_append_val(new_record->Answers, temp_answer);


      /* possible to check here for the auto_ptr and then to create
	 another record of the reversed address.in-addr.arpa and add
	 that to the lut as well.*/
      if(cfg_getbool(answer, "auto_ptr")) {
	gchar **ip_strv = g_strsplit(cfg_getstr(answer, "addr"), ".", 4);
	gchar *arpa_form_ip = g_strconcat("", NULL);
	int k = 0;
	for(k = 0; k < g_strv_length(ip_strv); k++) {
	  gchar *temp = g_strconcat(ip_strv[k], ".", arpa_form_ip, NULL);
	  g_free(arpa_form_ip);
	  arpa_form_ip = temp;
	}
	
	//find an existing record if one exists
	gchar *with_type = g_strconcat(arpa_form_ip, "in-addr.arpa:PTR", NULL);
	gchar *without_type = g_strconcat(arpa_form_ip, "in-addr.arpa", NULL);
	//g_message("looking for %s in lut", with_type);
	dns_resolver_record *auto_ptr_record = dns_lut_lookup(ret, with_type);

	if(auto_ptr_record == NULL) {
	  //make another record in in-addr.arpa ptr format
	  auto_ptr_record = dns_resolver_record_new();
	  //g_message("%s not found in lut", with_type);
	  auto_ptr_record->question.rr_type = DNS_QUESTION;
	  auto_ptr_record->question.Type = PTR;
	  auto_ptr_record->question.Class = question->Class;
	  auto_ptr_record->question.name = dns_name_make(without_type);
	  auto_ptr_record->ignore_non_auth_ok = TRUE;
	} else {
	  //g_message("%s found in lut", with_type);
	}

	dns_rr ptr_ans = {0};
	ptr_ans.rr_type = DNS_ANSWER;
	ptr_ans.Type = PTR;
	ptr_ans.Class = auto_ptr_record->question.Class;
	ptr_ans.name = dns_name_make(cfg_getstr(record, "host"));
	ptr_ans.DataLength = strlen(cfg_getstr(record, "host")) + 2;
	ptr_ans.TTL = cfg_getint(answer, "TTL");
	g_array_append_val(auto_ptr_record->Answers, ptr_ans);
	//g_message("inserting -%s- into running lut", with_type);
	g_hash_table_replace(ret.table, g_strdup(with_type), auto_ptr_record);

	g_free(with_type);
	g_free(without_type);
	g_free(arpa_form_ip);
      } else {
	//no automatically added ptr here
      }

    } /* for each answer on an a record */
    g_hash_table_insert(ret.table, g_strconcat(cfg_getstr(record, "host"), ":A", NULL), new_record);
  } /* for each a record */

///////////////////////////////////////////////////////////////////////
  for(i = 0; i < num_aaaa; i++) {
    cfg_t *record = cfg_getnsec(cfg, "aaaa_record", i);
    //create a record in memory
    dns_resolver_record *new_record = dns_resolver_record_new();
    //set the record name
    new_record->name = g_strdup(cfg_title(record));

    /* check for any requested flags for this record */
    new_record->request_authenticated = (cfg_getbool(record, "authenticated"))?TRUE:FALSE;
    new_record->request_authoratative = (cfg_getbool(record, "authoratative"))?TRUE:FALSE;
    new_record->ignore_non_auth_ok = (cfg_getbool(record, "ignore_authentication"))?TRUE:FALSE;

    /* now, put together the question. */
    dns_rr *question = &new_record->question;
    question->rr_type = DNS_QUESTION;
    question->Type = AAAA;
    question->Class = dns_class_from_ascii(cfg_getstr(record, "class"));
    question->name = dns_name_make(cfg_getstr(record, "host"));

    /* now, loop over each answer present, and make them and add
       themto the record */
    int num_answers = cfg_size(record, "answer");
    int j = 0;
    for(j=0; j < num_answers; j++) {
      cfg_t *answer = cfg_getnsec(record, "answer", j);
      dns_rr temp_answer = {0};
      temp_answer.rr_type = DNS_ANSWER;
      temp_answer.Type = AAAA;
      temp_answer.Class = question->Class;
      temp_answer.TTL = cfg_getint(answer, "TTL");
      temp_answer.name = dns_name_make(cfg_getstr(record, "host"));
      temp_answer.DataLength = 16;
      temp_answer.addr.type = DNS_IPV6;
      temp_answer.addr.address = g_strdup(cfg_getstr(answer, "addr"));
      g_array_append_val(new_record->Answers, temp_answer);
    } /* for each answer on an aaaa record */
    g_hash_table_insert(ret.table, g_strconcat(cfg_getstr(record, "host"), ":AAAA", NULL), new_record);
  } /* for each aaaa record */

///////////////////////////////////////////////////////////////////////////
  for(i = 0; i < num_mx; i++) {
    cfg_t *record = cfg_getnsec(cfg, "mx_record", i);
    //create a record in memory
    dns_resolver_record *new_record = dns_resolver_record_new();
    //set the record name
    new_record->name = g_strdup(cfg_title(record));

    /* check for any requested flags for this record */
    new_record->request_authenticated = (cfg_getbool(record, "authenticated"))?TRUE:FALSE;
    new_record->request_authoratative = (cfg_getbool(record, "authoratative"))?TRUE:FALSE;
    new_record->ignore_non_auth_ok = (cfg_getbool(record, "ignore_authentication"))?TRUE:FALSE;

    /* now, put together the question. */
    dns_rr *question = &new_record->question;
    question->rr_type = DNS_QUESTION;
    question->Type = MX;
    question->Class = dns_class_from_ascii(cfg_getstr(record, "class"));
    question->name = dns_name_make(cfg_getstr(record, "host"));

    /* now, loop over each answer present, and make them and add
       themto the record */
    int num_answers = cfg_size(record, "answer");
    int j = 0;
    for(j=0; j < num_answers; j++) {
      cfg_t *answer = cfg_getnsec(record, "answer", j);
      dns_rr temp_answer = {0};
      temp_answer.rr_type = DNS_ANSWER;
      temp_answer.Type = MX;
      temp_answer.Class = question->Class;
      temp_answer.name = dns_name_make(cfg_getstr(record, "host"));
      temp_answer.TTL = cfg_getint(answer, "TTL");
      temp_answer.Preference = cfg_getint(answer, "preference");
      temp_answer.mail_exchange = dns_name_make(cfg_getstr(answer, "exchange"));
      temp_answer.DataLength = strlen(cfg_getstr(answer, "exchange")) + 4;
      printf("data len on mx rec is %d\n", temp_answer.DataLength);
      g_array_append_val(new_record->Answers, temp_answer);
    } /* for each answer on an aaaa record */
    g_hash_table_insert(ret.table, g_strconcat(cfg_getstr(record, "host"), ":MX", NULL), new_record);
  } /* for each mx record */

///////////////////////////////////////////////////////////////////////////

  cfg_free(cfg);

  return ret;
}

dns_resolver_record *dns_lut_lookup(dns_lut lut, gchar *host_and_type) {
  dns_resolver_record *lookup = (dns_resolver_record*)g_hash_table_lookup(lut.table, host_and_type);
  return lookup;
}
