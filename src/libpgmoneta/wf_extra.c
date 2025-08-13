/*
 * Copyright (C) 2025 The pgmoneta community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pgmoneta.h>
#include <extension.h>
#include <logging.h>
#include <network.h>
#include <security.h>
#include <utils.h>
#include <workflow.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* extra_name(void);
static int extra_execute(char*, struct art*);

struct workflow*
pgmoneta_create_extra(void)
{
   struct workflow* wf = NULL;

   wf = (struct workflow*)malloc(sizeof(struct workflow));

   if (wf == NULL)
   {
      return NULL;
   }

   wf->name = &extra_name;
   wf->setup = &pgmoneta_common_setup;
   wf->execute = &extra_execute;
   wf->teardown = &pgmoneta_common_teardown;
   wf->next = NULL;

   return wf;
}

static char*
extra_name(void)
{
   return "Extra";
}

static int
extra_execute(char* name __attribute__((unused)), struct art* nodes)
{
   int server = -1;
   char* label = NULL;
   int usr;
   int socket = -1;
   double seconds;
   int minutes;
   int hours;
   double extra_elapsed_time;
   char elapsed[128];
   char* root = NULL;
   char* info_root = NULL;
   char* info_extra = NULL;
   struct timespec start_t;
   struct timespec end_t;
   SSL* ssl = NULL;
   struct main_configuration* config;
   struct query_response* qr = NULL;
   struct backup* backup = NULL;

   config = (struct main_configuration*)shmem;

#ifdef DEBUG
   pgmoneta_dump_art(nodes);

   assert(pgmoneta_art_contains_key(nodes, NODE_SERVER_ID));
   assert(pgmoneta_art_contains_key(nodes, NODE_LABEL));
   assert(pgmoneta_art_contains_key(nodes, NODE_BACKUP));
#endif

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &start_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &start_t);
#endif

   server = (int)pgmoneta_art_search(nodes, NODE_SERVER_ID);
   label = (char*)pgmoneta_art_search(nodes, NODE_LABEL);
   backup = (struct backup*)pgmoneta_art_search(nodes, NODE_BACKUP);

   if (config->common.servers[server].number_of_extra == 0)
   {
      pgmoneta_log_debug("No extra parameter are set for server: %s", config->common.servers[server].name);
      return 0;
   }

   pgmoneta_log_debug("Extra (execute): %s/%s", config->common.servers[server].name, label);

   // Create the root directory
   root = pgmoneta_get_server_extra_identifier(server, label);

   pgmoneta_memory_init();

   usr = -1;
   // find the corresponding user's index of the given server
   for (int i = 0; usr == -1 && i < config->common.number_of_users; i++)
   {
      if (!strcmp(config->common.servers[server].username, config->common.users[i].username))
      {
         usr = i;
      }
   }

   if (usr == -1)
   {
      pgmoneta_log_error("User not found for server: %d", server);
      goto error;
   }

   // establish a connection, with replication flag set
   if (pgmoneta_server_authenticate(server, "postgres", config->common.users[usr].username, config->common.users[usr].password, false, &ssl, &socket) != AUTH_SUCCESS)
   {
      pgmoneta_log_error("Authentication failed for user %s on %s", config->common.users[usr].username, config->common.servers[server].name);
      goto error;
   }

   pgmoneta_ext_is_installed(ssl, socket, &qr);
   if (qr == NULL || qr->tuples == NULL || qr->tuples->data == NULL || qr->tuples->data[0] == NULL || qr->tuples->data[2] == NULL || strcmp(qr->tuples->data[0], "pgmoneta_ext") != 0)
   {
      pgmoneta_log_warn("extra failed: Server %s does not have the pgmoneta_ext extension installed.", config->common.servers[server].name);
      goto error;
   }
   pgmoneta_free_query_response(qr);
   qr = NULL;

   for (int i = 0; i < config->common.servers[server].number_of_extra; i++)
   {
      if (pgmoneta_receive_extra_files(ssl, socket, config->common.servers[server].name, config->common.servers[server].extra[i], root, &info_extra) != 0)
      {
         pgmoneta_log_warn("extra failed: Server %s failed to retrieve extra files %s", config->common.servers[server].name, config->common.servers[server].extra[i]);
      }
   }

#ifdef HAVE_FREEBSD
   clock_gettime(CLOCK_MONOTONIC_FAST, &end_t);
#else
   clock_gettime(CLOCK_MONOTONIC_RAW, &end_t);
#endif

   extra_elapsed_time = pgmoneta_compute_duration(start_t, end_t);
   hours = (int)extra_elapsed_time / 3600;
   minutes = ((int)extra_elapsed_time % 3600) / 60;
   seconds = (int)extra_elapsed_time % 60 + (extra_elapsed_time - ((long)extra_elapsed_time));

   memset(&elapsed[0], 0, sizeof(elapsed));
   sprintf(&elapsed[0], "%02i:%02i:%.4f", hours, minutes, seconds);

   pgmoneta_log_debug("Extra: %s/%s (Elapsed: %s)", config->common.servers[server].name, label, &elapsed[0]);

   info_root = pgmoneta_get_server_backup(server);

   if (info_extra == NULL)
   {
      memset(backup->extra, 0, sizeof(backup->extra));
   }
   else
   {
      snprintf(backup->extra, sizeof(backup->extra), "%s", info_extra);
   }
   pgmoneta_log_debug("backup->label: %s", backup->label);
   if (pgmoneta_save_info(info_root, backup))
   {
      goto error;
   }
   free(root);
   free(info_root);
   if (info_extra != NULL)
   {
      free(info_extra);
   }
   pgmoneta_close_ssl(ssl);
   pgmoneta_disconnect(socket);
   pgmoneta_memory_destroy();

   return 0;

error:
   if (root != NULL)
   {
      free(root);
   }
   if (info_root != NULL)
   {
      free(info_root);
   }
   if (info_extra != NULL)
   {
      free(info_extra);
   }
   if (ssl != NULL)
   {
      pgmoneta_close_ssl(ssl);
   }
   if (socket != -1)
   {
      pgmoneta_disconnect(socket);
   }
   pgmoneta_memory_destroy();

   return 1;
}
