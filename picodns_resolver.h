/*
** picodns_resolver.h
** 
** Made by Adam
** Login   <adam@toxic.rh.rit.edu>
** 
** Started on  Fri Dec 12 16:27:58 2008 Adam
** Last update Fri Dec 12 16:27:58 2008 Adam
*/

#ifndef   	PICODNS_RESOLVER_H_
# define   	PICODNS_RESOLVER_H_

#include <glib.h>
#include <confuse.h>

#include "picodns_types.h"

static cfg_opt_t a_answer_opts[] = {
  CFG_INT("TTL", 3600, CFGF_NONE),
  CFG_BOOL("auto_ptr", TRUE, CFGF_NONE),
  CFG_STR("addr", 0, CFGF_NONE),
  CFG_END()
};

static cfg_opt_t aaaa_answer_opts[] = {
  CFG_INT("TTL", 3600, CFGF_NONE),
  CFG_STR("addr", 0, CFGF_NONE),
  CFG_END()
};

static cfg_opt_t mx_answer_opts[] = {
  CFG_INT("TTL", 3600, CFGF_NONE),
  CFG_INT("preference", 0, CFGF_NONE),
  CFG_STR("exchange", 0, CFGF_NONE),
  CFG_END()
};

static cfg_opt_t a_record_opts[] = {
  CFG_STR("host", 0, CFGF_NONE),
  CFG_STR("class", "IN", CFGF_NONE),
  CFG_BOOL("authoratative", 0, CFGF_NONE),
  CFG_BOOL("authenticated", 0, CFGF_NONE),
  CFG_BOOL("ignore_authentication", 0, CFGF_NONE),
  CFG_SEC("answer", a_answer_opts, CFGF_MULTI),
  CFG_END()
};

static cfg_opt_t aaaa_record_opts[] = {
  CFG_STR("host", 0, CFGF_NONE),
  CFG_STR("class", "IN", CFGF_NONE),
  CFG_BOOL("authoratative", 0, CFGF_NONE),
  CFG_BOOL("authenticated", 0, CFGF_NONE),
  CFG_BOOL("ignore_authentication", 0, CFGF_NONE),
  CFG_SEC("answer", aaaa_answer_opts, CFGF_MULTI),
  CFG_END()
};

static cfg_opt_t mx_record_opts[] = {
  CFG_STR("host", 0, CFGF_NONE),
  CFG_STR("class", "IN", CFGF_NONE),
  CFG_BOOL("authoratative", 0, CFGF_NONE),
  CFG_BOOL("authenticated", 0, CFGF_NONE),
  CFG_BOOL("ignore_authentication", 0, CFGF_NONE),
  CFG_SEC("answer", mx_answer_opts, CFGF_MULTI),
  CFG_END()
};

static cfg_opt_t opts[] = {
  CFG_SEC("a_record", a_record_opts, CFGF_MULTI | CFGF_TITLE),
  CFG_SEC("aaaa_record", aaaa_record_opts, CFGF_MULTI | CFGF_TITLE),
  CFG_SEC("mx_record", mx_record_opts, CFGF_MULTI | CFGF_TITLE),
  CFG_FUNC("include", &cfg_include),
  CFG_END()
};

dns_lut dns_lut_new(char *filepath);
dns_resolver_record *dns_lut_lookup(dns_lut lut, gchar *host);
#endif 	    /* !PICODNS_RESOLVER_H_ */
