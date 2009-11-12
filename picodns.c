/*
** picodns.c
** 
** Made by (Adam)
** Login   <adam@toxic.rh.rit.edu>
** 
** Started on  Mon Nov  3 20:26:08 2008 Adam
** Last update Sun May 12 01:17:25 2002 Speed Blue
*/

#include "picodns_util.h"
#include "picodns_config.h"
#include "picodns_resolver.h"
#include "picodns_types.h"
#include "picodns.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <glib.h>


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char **argv) {
  char *main_config_file = argv[1] != NULL ? argv[1] : "config.pdns";

  g_message("picodns starting...");
  int read_config_result = 0;
  if((read_config_result = read_config(main_config_file)) != 0) {
    g_error("Could not read the main configuration file %s", main_config_file);
  } else {
    g_message("Read main configuration file %s", main_config_file);
  }

  g_message("loading LUT from file %s...", main_records_file);

  //load the lookup table
  dns_lut lut = dns_lut_new(main_records_file);
  
  g_message("LUT loaded (%d entries)", g_hash_table_size(lut.table));

  int sockfd;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int numbytes;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  char s[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  char port[7] = {0};
  sprintf(port, "%d", udp_port);
  if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) == -1) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  
  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) == -1) {
      perror("listener: socket");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("listener: bind");
      continue;
    }

    break;
  }

  if (p == NULL) {
    g_error("could not bind to socket");
  }
  
  g_message("picodns loaded, waiting for requests");
  
  addr_len = sizeof their_addr;

  while(1) {
    //create the gbytearray for storage of incoming udp packet
    GByteArray *packet_data = g_byte_array_sized_new(max_incoming_udp_packet_size);
    if ((numbytes = recvfrom(sockfd, packet_data->data, max_incoming_udp_packet_size, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
      g_warning("Error receiving data: ");
      perror("recvfrom");
      continue;
    }
    g_byte_array_set_size(packet_data, numbytes);

    //set s to contain string rep of src address
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
    g_debug("dns request from %s", s);
    if(localhost_only == TRUE) {
      if((strcmp(s, "127.0.0.1") != 0) &&
	 (strcmp(s, "::1") != 0) &&
	 (strcmp(s, "::ffff:127.0.0.1") != 0)) {
	//this is not from localhost, and only localhost is allowed,
	// so ignore it
	continue;
      }
    }
    
    //now we parse apart he packet into its respective parts.
    dns_packet packet = dns_packet_parse(packet_data);
    //dns_packet_print(&packet);
    
    //extract the target hostname from the packet
    if(packet.QuestionRRCount > 1) {
      g_warning("got a dns packet with more than one question in it, ignoring");
      continue;
    } else if (packet.QuestionRRCount  == 0) {
      g_warning("got a dns packet without a question, ignoring");
      continue;
    }
    
    dns_rr question = g_array_index(packet.QuestionRRs, dns_rr, 0);    

    gchar *target_host = g_strconcat(dns_name_to_ascii(question.name), ":", dns_type_to_ascii(question.Type), NULL);
    
    g_message("got a query for %s", target_host);
    
    //now, we resolve the packet into a responce packet
    dns_resolver_record *resolved = dns_lut_lookup(lut, target_host);
    
    //make a new dns_packet with the question as well as the answer
    dns_packet reply = dns_packet_new();
    reply.TransactionID = packet.TransactionID;
    
    //flags start as a mirror of the recv'd packets flags
    reply.flags = packet.flags;
    reply.flags.Responce = DNS_RESPONCE;
    reply.flags.Authoritative = 0;
    reply.flags.Truncated = 0;
    reply.flags.RecursionAvailable = 0;
    reply.flags.AnswerAuthenticated = 0;
    reply.flags.ReplyCode = 0;


    //add the query
    reply.QuestionRRCount = 1;
    dns_rr question_rr = g_array_index(packet.QuestionRRs, dns_rr, 0);
    g_array_append_val(reply.QuestionRRs, question_rr);

    if(resolved == NULL) {
      g_message("DNS LUT has no entry for %s", target_host);
    } else {
      //if NonAuthOK is 0, then Authentication is required - in this
      //case, we can only reply if the resolver_record states that
      //request_authenticated is set. If it isnt, then the record isnt
      //considered authenticated, and isnt an appropriate responce.
      
      if((resolved->request_authenticated && !packet.flags.NonAuthOK) ||
	 (packet.flags.NonAuthOK) || 
	 (!packet.flags.NonAuthOK && resolved->ignore_non_auth_ok)) {
	//set the requested flags
	reply.flags.Authoritative = (resolved->request_authoratative)?1:0;
	reply.flags.AnswerAuthenticated = (resolved->request_authenticated)?1:0;
	//now, insert each one of the answers into the reply packet
	reply.AnswerRRCount = resolved->Answers->len;
	g_array_append_vals(reply.AnswerRRs, resolved->Answers->data, resolved->Answers->len);
	g_message("DNS LUT has %d answer(s) matching %s", resolved->Answers->len, target_host);
      } else {
	g_message("DNS LUT has no appropriate entry for %s", target_host);
      }
    }
    
    //now, pack the responce packet into a GByteArray
    GByteArray *reply_data = dns_packet_pack(&reply);
    
    //now, we transmit the responce packet
    if ((numbytes = sendto(sockfd, reply_data->data, reply_data->len, 0,
    		   (struct sockaddr *)&their_addr, addr_len)) == -1) {
      perror("talker: sendto");
     exit(1);
    }

    //now we clean up!
    g_byte_array_free(packet_data, TRUE);
  } /* end main server loop */

  freeaddrinfo(servinfo);  
 
  //close the DNS socket file descriptor
  close(sockfd);

  free_config();  

  return 0;
}
