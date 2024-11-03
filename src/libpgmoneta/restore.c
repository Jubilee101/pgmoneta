/*
 * Copyright (C) 2024 The pgmoneta community
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

/* pgmoneta */
#include <pgmoneta.h>
#include <deque.h>
#include <info.h>
#include <logging.h>
#include <management.h>
#include <network.h>
#include <restore.h>
#include <string.h>
#include <utils.h>
#include <value.h>
#include <workflow.h>

/* system */
#include <stdlib.h>
#include <unistd.h>

#define INCREMENTAL_MAGIC 0xd3ae1f0d

/**
 * An rfile stores the metadata we need to use a file on disk for reconstruction.
 * For full backup file in the chain, only file name and file pointer are initialized.
 *
 * num_blocks is the number of blocks present inside an incremental file.
 * These are the blocks that have changed since the last checkpoint.
 * truncation_block_length is basically the shortest length this file has been between this and last checkpoint.
 * Note that truncation_block_length could be even greater than the number of blocks the original file has.
 * Because the tables are not locked during the backup, so blocks could be truncated during the process,
 * while truncation_block_length only reflects length until the checkpoint before backup starts.
 * relative_block_numbers are the relative BlockNumber of each block in the file. Relative here means relative to
 * the starting BlockNumber of this file.
 */
struct rfile
{
   char* filename;
   FILE* fp;
   size_t header_length;
   uint32_t num_blocks;
   uint32_t* relative_block_numbers;
   uint32_t truncation_block_length;
};

static char* restore_last_files_names[] = {"/global/pg_control"};
/**
 * Reconstruct an incremental backup file from itself and its prior incremental/full backup files to a full backup file
 * @param server The server
 * @param input_file_path The path to the incremental backup file
 * @param output_file_path The path to the reconstructed full backup file
 * @param relative_dir The directory containing the incremental file relative to the root dir, should be the same across all backups
 * @param bare_file_name The name of the file without "INCREMENTAL." prefix
 * @param prior_backups_num The number of prior incremental/full backups
 * @param prior_backup_dirs The root directory of prior incremental/full backups
 * @return 0 on success, 1 if otherwise
 */
static int
reconstruct_backup_file(int server,
                        char* input_file_path,
                        char* output_file_path,
                        char* relative_dir,
                        char* bare_file_name,
                        int prior_backups_num,
                        char** prior_backup_dirs);

/**
 * Get the number of blocks that the final reconstructed full backup file should have.
 * Normally it is the same as truncation_block_length. But new blocks could have been
 * added after the table was truncated to truncation_block_length. Or it was
 * newly created and later got data inserted. So anyway extend the file length to include
 * those blocks.
 *
 * Note that even if a block of data is deleted it still counts as modified,
 * since PostgreSQL doesn't actually delete the block.
 * @param s The rfile of the incremental file
 * @return The block length
 */
static uint32_t
find_reconstructed_block_length(struct rfile* s);

static void
rfile_create(struct rfile** rfile);

static void
rfile_destroy(struct rfile* rf);

static int
rfile_initialize(int server, char* file_path, struct rfile** rf);

int
pgmoneta_get_restore_last_files_names(char*** output)
{
   int number_of_elements = 0;
   number_of_elements = sizeof(restore_last_files_names) / sizeof(restore_last_files_names[0]);

   *output = (char**)malloc((number_of_elements + 1) * sizeof(char*));
   if (*output == NULL)
   {
      return 1;
   }

   for (int i = 0; i < number_of_elements; i++)
   {
      (*output)[i] = strdup(restore_last_files_names[i]);
      if ((*output)[i] == NULL)
      {
         return 1;
      }
   }
   (*output)[number_of_elements] = NULL;

   return 0;
}

void
pgmoneta_restore(SSL* ssl, int client_fd, int server, uint8_t compression, uint8_t encryption, struct json* payload)
{
   char* identifier = NULL;
   char* position = NULL;
   char* directory = NULL;
   char* elapsed = NULL;
   time_t start_time;
   time_t end_time;
   int total_seconds = 0;
   char* output = NULL;
   char* label = NULL;
   char* server_backup = NULL;
   struct backup* backup = NULL;
   struct json* req = NULL;
   struct json* response = NULL;
   struct configuration* config;

   pgmoneta_start_logging();

   config = (struct configuration*)shmem;

   start_time = time(NULL);

   atomic_fetch_add(&config->active_restores, 1);
   atomic_fetch_add(&config->servers[server].restore, 1);

   req = (struct json*)pgmoneta_json_get(payload, MANAGEMENT_CATEGORY_REQUEST);
   identifier = (char*)pgmoneta_json_get(req, MANAGEMENT_ARGUMENT_BACKUP);
   position = (char*)pgmoneta_json_get(req, MANAGEMENT_ARGUMENT_POSITION);
   directory = (char*)pgmoneta_json_get(req, MANAGEMENT_ARGUMENT_DIRECTORY);

   if (!pgmoneta_restore_backup(server, identifier, position, directory, &output, &label))
   {
      if (pgmoneta_management_create_response(payload, server, &response))
      {
         pgmoneta_management_response_error(NULL, client_fd, config->servers[server].name, MANAGEMENT_ERROR_ALLOCATION, compression, encryption, payload);

         goto error;
      }

      server_backup = pgmoneta_get_server_backup(server);

      if (pgmoneta_get_backup(server_backup, label, &backup))
      {
         pgmoneta_management_response_error(NULL, client_fd, config->servers[server].name, MANAGEMENT_ERROR_RESTORE_ERROR, compression, encryption, payload);

         goto error;
      }

      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_SERVER, (uintptr_t)config->servers[server].name, ValueString);
      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BACKUP, (uintptr_t)backup->label, ValueString);
      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_BACKUP_SIZE, (uintptr_t)backup->backup_size, ValueUInt64);
      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_RESTORE_SIZE, (uintptr_t)backup->restore_size, ValueUInt64);
      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_COMMENTS, (uintptr_t)backup->comments, ValueString);
      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_COMPRESSION, (uintptr_t)backup->compression, ValueInt32);
      pgmoneta_json_put(response, MANAGEMENT_ARGUMENT_ENCRYPTION, (uintptr_t)backup->encryption, ValueInt32);

      end_time = time(NULL);

      if (pgmoneta_management_response_ok(NULL, client_fd, start_time, end_time, compression, encryption, payload))
      {
         pgmoneta_management_response_error(NULL, client_fd, config->servers[server].name, MANAGEMENT_ERROR_RESTORE_NETWORK, compression, encryption, payload);
         pgmoneta_log_error("Restore: Error sending response for %s", config->servers[server].name);

         goto error;
      }

      elapsed = pgmoneta_get_timestamp_string(start_time, end_time, &total_seconds);
      pgmoneta_log_info("Restore: %s/%s (Elapsed: %s)", config->servers[server].name, backup->label, elapsed);
   }

   pgmoneta_json_destroy(payload);

   pgmoneta_disconnect(client_fd);

   atomic_fetch_sub(&config->servers[server].restore, 1);
   atomic_fetch_sub(&config->active_restores, 1);

   pgmoneta_stop_logging();

   free(backup);
   free(elapsed);
   free(server_backup);
   free(output);

   exit(0);

error:

   pgmoneta_json_destroy(payload);

   pgmoneta_disconnect(client_fd);

   atomic_fetch_sub(&config->servers[server].restore, 1);
   atomic_fetch_sub(&config->active_restores, 1);

   pgmoneta_stop_logging();

   free(backup);
   free(elapsed);
   free(server_backup);
   free(output);

   exit(1);
}

int
pgmoneta_restore_backup(int server, char* identifier, char* position, char* directory, char** output, char** label)
{
   char* o = NULL;
   struct workflow* workflow = NULL;
   struct workflow* current = NULL;
   struct deque* nodes = NULL;
   struct backup* backup = NULL;

   *output = NULL;
   *label = NULL;

   pgmoneta_deque_create(false, &nodes);

   if (pgmoneta_deque_add(nodes, NODE_POSITION, (uintptr_t)position, ValueString))
   {
      goto error;
   }

   if (pgmoneta_deque_add(nodes, NODE_DIRECTORY, (uintptr_t)directory, ValueString))
   {
      goto error;
   }

   if (pgmoneta_workflow_nodes(server, identifier, nodes, &backup))
   {
      goto error;
   }

   workflow = pgmoneta_workflow_create(WORKFLOW_TYPE_RESTORE, backup);

   current = workflow;
   while (current != NULL)
   {
      if (current->setup(server, identifier, nodes))
      {
         goto error;
      }
      current = current->next;
   }

   current = workflow;
   while (current != NULL)
   {
      if (current->execute(server, identifier, nodes))
      {
         goto error;
      }
      current = current->next;
   }

   current = workflow;
   while (current != NULL)
   {
      if (current->teardown(server, identifier, nodes))
      {
         goto error;
      }
      current = current->next;
   }

   o = (char*)pgmoneta_deque_get(nodes, NODE_OUTPUT);

   if (o == NULL)
   {
      goto error;
   }

   *output = malloc(strlen(o) + 1);

   if (*output == NULL)
   {
      goto error;
   }

   memset(*output, 0, strlen(o) + 1);
   memcpy(*output, o, strlen(o));

   *label = malloc(strlen(backup->label) + 1);

   if (*label == NULL)
   {
      goto error;
   }

   memset(*label, 0, strlen(backup->label) + 1);
   memcpy(*label, backup->label, strlen(backup->label));

   free(backup);

   pgmoneta_workflow_destroy(workflow);

   pgmoneta_deque_destroy(nodes);

   return 0;

error:
   free(backup);

   pgmoneta_workflow_destroy(workflow);

   pgmoneta_deque_destroy(nodes);

   return 1;
}

static int
reconstruct_backup_file(int server,
                        char* input_file_path,
                        char* output_file_path,
                        char* relative_dir,
                        char* bare_file_name,
                        int prior_backups_num,
                        char** prior_backup_dirs)
{

   return 0;
error:
   return 1;
}

static uint32_t
find_reconstructed_block_length(struct rfile* s)
{
   uint32_t block_length = 0;
   if (s == NULL)
   {
      return 0;
   }
   block_length = s->truncation_block_length;
   for (int i = 0; i < s->num_blocks; i++)
   {
      if (s->relative_block_numbers[i] >= block_length)
      {
         block_length = s->relative_block_numbers[i] + 1;
      }
   }

   return block_length;
}

static void
rfile_create(struct rfile** rfile)
{
   struct rfile* rf = NULL;
   rf = (struct rfile*) malloc(sizeof(struct rfile));
   memset(rf, 0, sizeof(struct rfile));
   *rfile = rf;
}

static void
rfile_destroy(struct rfile* rf)
{
   if (rf == NULL)
   {
      return;
   }
   if (rf->fp != NULL)
   {
      fclose(rf->fp);
   }
   free(rf->filename);
   free(rf->relative_block_numbers);
   free(rf);
}

static int
rfile_initialize(int server, char* file_path, struct rfile** rfile)
{
   FILE* fp = NULL;
   uint32_t magic = 0;
   int nread = 0;
   struct rfile* rf = NULL;
   struct configuration* config;
   size_t relsegsz = 0;
   size_t blocksz = 0;

   config = (struct configuration*)shmem;

   relsegsz = config->servers[server].relseg_size;
   blocksz = config->servers[server].block_size;

   fp = fopen(file_path, "r");
   if (fp == NULL)
   {
      pgmoneta_log_error("rfile initialize: failed to open incremental backup file at %s", file_path);
      goto error;
   }

   // create rfile after file is opened successfully
   rfile_create(&rf);
   rf->fp = fp;

   // read magic number from header
   nread = fread(&magic, 1, sizeof(uint32_t), fp);
   if (nread != sizeof(uint32_t))
   {
      pgmoneta_log_error("rfile initialize: incomplete file header at %s, cannot read magic number", file_path);
      goto error;
   }

   if (magic != INCREMENTAL_MAGIC)
   {
      pgmoneta_log_error("rfile initialize: incorrect magic number, getting %X, expecting %X", magic, INCREMENTAL_MAGIC);
      goto error;
   }

   // read number of blocks
   nread = fread(&rf->num_blocks, 1, sizeof(uint32_t), fp);
   if (nread != sizeof(uint32_t))
   {
      pgmoneta_log_error("rfile initialize: incomplete file header at %s, cannot read block count", file_path);
      goto error;
   }
   if (rf->num_blocks > relsegsz)
   {
      pgmoneta_log_error("rfile initialize: file has %d blocks which is more than server's segment size", rf->num_blocks);
      goto error;
   }

   // read truncation block length
   nread = fread(&rf->truncation_block_length, 1, sizeof(uint32_t), fp);
   if (nread != sizeof(uint32_t))
   {
      pgmoneta_log_error("rfile initialize: incomplete file header at %s, cannot read truncation block length", file_path);
      goto error;
   }
   if (rf->truncation_block_length > relsegsz)
   {
      pgmoneta_log_error("rfile initialize: file has truncation block length of %d which is more than server's segment size", rf->truncation_block_length);
      goto error;
   }

   if (rf->num_blocks > 0)
   {
      rf->relative_block_numbers = malloc(sizeof(uint32_t) * rf->num_blocks);
      nread = fread(rf->relative_block_numbers, sizeof(uint32_t), rf->num_blocks, fp);
      if (nread != rf->num_blocks)
      {
         pgmoneta_log_error("rfile initialize: incomplete file header at %s, cannot read relative block numbers", file_path);
         goto error;
      }
   }

   // magic + block num + truncation block length + relative block numbers
   rf->header_length = sizeof(uint32_t) * (1 + 1 + 1 + rf->num_blocks);
   // round header length to multiple of block size, since the actual file data are aligned
   // only needed when the file actually has data
   if (rf->num_blocks > 0 && rf->header_length % blocksz != 0)
   {
      rf->header_length += (blocksz - (rf->header_length % blocksz));
   }

   rf->filename = pgmoneta_append(NULL, file_path);
   *rfile = rf;

   return 0;
error:
   // contains fp closing logic
   rfile_destroy(rf);
   return 1;
}