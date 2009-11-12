/*
** picodns_config.h
** 
** Made by Adam
** Login   <adam@toxic.rh.rit.edu>
** 
** Started on  Sat Dec 13 18:20:53 2008 Adam
** Last update Sat Dec 13 18:20:53 2008 Adam
*/

#ifndef   	PICODNS_CONFIG_H_
# define   	PICODNS_CONFIG_H_

#include <confuse.h>
#include <glib.h>


extern int udp_port;
extern char *main_records_file;
extern int max_incoming_udp_packet_size;
extern gboolean localhost_only;

static cfg_opt_t main_config_opts[] = {
  CFG_INT("udp_port", 53, CFGF_NONE),
  CFG_BOOL("localhost_only", cfg_true, CFGF_NONE),
  CFG_STR("main_records_file", "records.pdns", CFGF_NONE),
  CFG_INT("max_incoming_udp_packet_size", 512, CFGF_NONE),
  CFG_END()
};

int read_config(char *filepath);
void free_config(void);

#endif 	    /* !PICODNS_CONFIG_H_ */
