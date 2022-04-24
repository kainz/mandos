/*  -*- coding: utf-8 -*- */
/* 
 * iprouteadddel - Add or delete direct route to a local IP address
 * 
 * Copyright © 2015-2018, 2021-2022 Teddy Hogeborn
 * Copyright © 2015-2018, 2021-2022 Björn Påhlsson
 * 
 * This file is part of Mandos.
 * 
 * Mandos is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Mandos is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Mandos.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Contact the authors at <mandos@recompile.se>.
 */

#define _GNU_SOURCE		/* program_invocation_short_name */
#include <stdbool.h>		/* bool, false, true */
#include <argp.h>		/* argp_program_version,
				   argp_program_bug_address,
				   struct argp_option,
				   struct argp_state, ARGP_KEY_ARG,
				   argp_usage(), ARGP_KEY_END,
				   ARGP_ERR_UNKNOWN, struct argp,
				   argp_parse(), ARGP_IN_ORDER */
#include <errno.h>		/* errno,
				   program_invocation_short_name,
				   error_t, EINVAL, ENOMEM */
#include <stdio.h>		/* fprintf(), stderr, perror(), FILE,
				   vfprintf() */
#include <stdarg.h>		/* va_list, va_start(), vfprintf() */
#include <stdlib.h>		/* EXIT_SUCCESS */
#include <netlink/netlink.h>	/* struct nl_addr, nl_addr_parse(),
				   nl_geterror(),
				   nl_addr_get_family(), NLM_F_EXCL,
				   nl_addr_put() */
#include <stddef.h>		/* NULL */
#include <netlink/route/route.h>/* struct rtnl_route,
				   struct rtnl_nexthop, NETLINK_ROUTE,
				   rtnl_route_alloc(),
				   rtnl_route_set_family(),
				   rtnl_route_set_protocol(),
				   RTPROT_BOOT,
				   rtnl_route_set_scope(),
				   RT_SCOPE_LINK,
				   rtnl_route_set_type(), RTN_UNICAST,
				   rtnl_route_set_dst(),
				   rtnl_route_set_table(),
				   RT_TABLE_MAIN,
				   rtnl_route_nh_alloc(),
				   rtnl_route_nh_set_ifindex(),
				   rtnl_route_add_nexthop(),
				   rtnl_route_add(),
				   rtnl_route_delete(),
				   rtnl_route_put(),
				   rtnl_route_nh_free() */
#include <netlink/socket.h>	/* struct nl_sock, nl_socket_alloc(),
				   nl_connect(), nl_socket_free() */
#include <strings.h>		/* strcasecmp() */
#include <sys/socket.h>		/* AF_UNSPEC, AF_INET6, AF_INET */
#include <sysexits.h>		/* EX_USAGE, EX_OSERR */
#include <netlink/route/link.h> /* struct rtnl_link,
				   rtnl_link_get_kernel(),
				   rtnl_link_get_ifindex(),
				   rtnl_link_put() */
#include <netinet/in.h>		/* sa_family_t */
#include <inttypes.h>		/* PRIdMAX, intmax_t */
#include <stdint.h>		/* uint8_t */


bool debug = false;
const char *argp_program_version = "mandos-client-iprouteadddel " VERSION;
const char *argp_program_bug_address = "<mandos@recompile.se>";

/* Function to use when printing errors */
void perror_plus(const char *print_text){
  int e = errno;
  fprintf(stderr, "Mandos plugin helper %s: ",
	  program_invocation_short_name);
  errno = e;
  perror(print_text);
}

__attribute__((format (gnu_printf, 2, 3), nonnull))
int fprintf_plus(FILE *stream, const char *format, ...){
  va_list ap;
  va_start(ap, format);
  
  fprintf(stream, "Mandos plugin helper %s: ",
	  program_invocation_short_name);
  return vfprintf(stream, format, ap);
}

int main(int argc, char *argv[]){
  int ret;
  int exitcode = EXIT_SUCCESS;
  struct arguments {
    bool add;			/* true: add, false: delete */
    char *address;		/* IP address as string */
    struct nl_addr *nl_addr;	/* Netlink IP address */
    char *interface;		/* interface name */
  } arguments = { .add = true, .address = NULL, .interface = NULL };
  struct argp_option options[] = {
    { .name = "debug", .key = 128,
      .doc = "Debug mode" },
    { .name = NULL }
  };
  struct rtnl_route *route = NULL;
  struct rtnl_nexthop *nexthop = NULL;
  struct nl_sock *sk = NULL;
  
  error_t parse_opt(int key, char *arg, struct argp_state *state){
    int lret;
    errno = 0;
    switch(key){
    case 128:			/* --debug */
      debug = true;
      break;
    case ARGP_KEY_ARG:
      switch(state->arg_num){
      case 0:
	if(strcasecmp(arg, "add") == 0){
	  ((struct arguments *)(state->input))->add = true;
	} else if(strcasecmp(arg, "delete") == 0){
	  ((struct arguments *)(state->input))->add = false;
	} else {
	  fprintf_plus(stderr, "Unrecognized command: %s\n", arg);
	  argp_usage(state);
	}
	break;
      case 1:
	((struct arguments *)(state->input))->address = arg;
	lret = nl_addr_parse(arg, AF_UNSPEC, &(((struct arguments *)
						(state->input))
					       ->nl_addr));
	if(lret != 0){
	  fprintf_plus(stderr, "Failed to parse address %s: %s\n",
		       arg, nl_geterror(lret));
	  argp_usage(state);
	}
	break;
      case 2:
	((struct arguments *)(state->input))->interface = arg;
	break;
      default:
	argp_usage(state);
      }
      break;
    case ARGP_KEY_END:
      if(state->arg_num < 3){
	argp_usage(state);
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return errno;
  }
  
  struct argp argp = { .options = options, .parser = parse_opt,
		       .args_doc = "[ add | delete ] ADDRESS INTERFACE",
		       .doc = "Mandos client helper -- Add or delete"
		       " local route to IP address on interface" };
  
  ret = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &arguments);
  switch(ret){
  case 0:
    break;
  case EINVAL:
    exit(EX_USAGE);
  case ENOMEM:
  default:
    errno = ret;
    perror_plus("argp_parse");
    exitcode = EX_OSERR;
    goto end;
  }
  /* Get netlink socket */
  sk = nl_socket_alloc();
  if(sk == NULL){
    fprintf_plus(stderr, "Failed to allocate netlink socket: %s\n",
		 nl_geterror(ret));
    exitcode = EX_OSERR;
    goto end;
  }
  /* Connect socket to netlink */
  ret = nl_connect(sk, NETLINK_ROUTE);
  if(ret < 0){
    fprintf_plus(stderr, "Failed to connect socket to netlink: %s\n",
		 nl_geterror(ret));
    exitcode = EX_OSERR;
    goto end;
  }
  /* Get link object of specified interface */
  struct rtnl_link *link = NULL;
  ret = rtnl_link_get_kernel(sk, 0, arguments.interface, &link);
  if(ret < 0){
    fprintf_plus(stderr, "Failed to use interface %s: %s\n",
		 arguments.interface, nl_geterror(ret));
    exitcode = EX_OSERR;
    goto end;
  }
  /* Get netlink route object */
  route = rtnl_route_alloc();
  if(route == NULL){
    fprintf_plus(stderr, "Failed to get netlink route:\n");
    exitcode = EX_OSERR;
    goto end;
  }
  /* Get address family of specified address */
  sa_family_t af = (sa_family_t)nl_addr_get_family(arguments.nl_addr);
  if(debug){
    fprintf_plus(stderr, "Address family of %s is %s (%" PRIdMAX
		 ")\n", arguments.address,
		 af == AF_INET6 ? "AF_INET6" :
		 ( af == AF_INET ? "AF_INET" : "UNKNOWN"),
		 (intmax_t)af);
  }
  /* Set route parameters: */
  rtnl_route_set_family(route, (uint8_t)af);   /* Address family */
  rtnl_route_set_protocol(route, RTPROT_BOOT); /* protocol - see
						  ip-route(8) */
  rtnl_route_set_scope(route, RT_SCOPE_LINK); /* link scope */
  rtnl_route_set_type(route, RTN_UNICAST);    /* normal unicast
						 address route */
  rtnl_route_set_dst(route, arguments.nl_addr); /* Destination
						   address */
  rtnl_route_set_table(route, RT_TABLE_MAIN); /* "main" routing
						 table */
  /* Create nexthop */
  nexthop = rtnl_route_nh_alloc();
  if(nexthop == NULL){
    fprintf_plus(stderr, "Failed to get netlink route nexthop\n");
    exitcode = EX_OSERR;
    goto end;
  }
  /* Get index number of specified interface */
  int ifindex = rtnl_link_get_ifindex(link);
  if(debug){
    fprintf_plus(stderr, "ifindex of %s is %d\n", arguments.interface,
		 ifindex);
  }
  /* Set interface index number on nexthop object */
  rtnl_route_nh_set_ifindex(nexthop, ifindex);
  /* Set route to use nexthop object */
  rtnl_route_add_nexthop(route, nexthop);
  /* Add or delete route? */
  if(arguments.add){
    ret = rtnl_route_add(sk, route, NLM_F_EXCL);
  } else {
    ret = rtnl_route_delete(sk, route, 0);
  }
  if(ret < 0){
     fprintf_plus(stderr, "Failed to %s route: %s\n",
		  arguments.add ? "add" : "delete",
		  nl_geterror(ret));
    exitcode = EX_OSERR;
    goto end;
  }
 end:
  /* Deallocate route */
  if(route){
    rtnl_route_put(route);
  } else if(nexthop) {
    /* Deallocate route nexthop */
    rtnl_route_nh_free(nexthop);
  }
  /* Deallocate parsed address */
  if(arguments.nl_addr){
    nl_addr_put(arguments.nl_addr);
  }
  /* Deallocate link struct */
  if(link){
    rtnl_link_put(link);
  }
  /* Deallocate netlink socket struct */
   if(sk){
    nl_socket_free(sk);
  }
  return exitcode;
}
