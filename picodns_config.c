/*
** picodns_config.c
** 
** Made by (Adam)
** Login   <adam@toxic.rh.rit.edu>
** 
** Started on  Sat Dec 13 18:20:42 2008 Adam
** Last update Sun May 12 01:17:25 2002 Speed Blue
*/

#include <glib.h>
#include <confuse.h>
#include "picodns_config.h"

int udp_port = 53;
char *main_records_file = "records.pdns";
int max_incoming_udp_packet_size = 512;
gboolean localhost_only = TRUE;

//read the main configuration file and set the global variables
int read_config(char *filepath) {
  cfg_t *cfg;
  int ret = 1;

  cfg = cfg_init(main_config_opts, CFGF_NOCASE);
  
  ret = cfg_parse(cfg, filepath);
  if(ret == CFG_FILE_ERROR) {
    perror("test.conf");
    return 1;
  } else if(ret == CFG_PARSE_ERROR) {
    fprintf(stderr, "parse error\n");
    return 1; 
  }

  //set the global variables
  udp_port = cfg_getint(cfg, "udp_port");
  main_records_file = g_strdup(cfg_getstr(cfg, "main_records_file"));
  max_incoming_udp_packet_size = cfg_getint(cfg, "max_incoming_udp_packet_size");
  if(cfg_getbool(cfg, "localhost_only")) {
    g_message("picodns will only serve to localhost");
    localhost_only = TRUE;
  } else {
    g_message("picodns not limited to only localhost");
    localhost_only = FALSE;
  }

  cfg_free(cfg);
  return 0;
}

//free the memory taken up by the config variables
void free_config() {
  g_free(main_records_file);
}
  
