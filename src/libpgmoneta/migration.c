/*
 * Copyright (C) 2026 The pgmoneta community
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
#include <aes.h>
#include <art.h>
#include <info.h>
#include <json.h>
#include <logging.h>
#include <migration.h>
#include <utils.h>

// system
#include <assert.h>
#include <stdio.h>
#include <time.h>

#define PGBACKREST_BACKUP_INFO "backup.info"
#define CBC_DIGEST_DEFAULT     "sha1"

struct pgbackrest_backup_info
{
   char* lsn_start;
   char* lsn_stop;
   char* archive_start;
   char* archive_stop;
   char* backup_id;
   char** backup_chain; // from oldest to newest
   int backup_chain_size;
   char* backup_parent;
   size_t restore_size;
   time_t start_time;
   int type;
};

static int decrypt_backup_info(char* source_dir, char* workspace);
static void build_target_dir(char* source_dir, char* server, char** target_dir);
static int migrate_pgbackrest(char* source_dir, char* backup_id, char* server, char* workspace);

static int pgbackrest_backup_info_create(char* backup_id, struct json* info, struct pgbackrest_backup_info** backup);
static void pgbackrest_backup_info_destroy(struct pgbackrest_backup_info* backup);
static void pgbackrest_backup_info_destroy_cb(uintptr_t data);

int
pgmoneta_migrate(char* source_dir, char* backup_id, char* server, char* workspace)
{
   struct muse_configuration* config = NULL;

   config = (struct muse_configuration*)shmem;
   if (config->source_tool == TOOL_PGBACKREST)
   {
      return migrate_pgbackrest(source_dir, backup_id, server, workspace);
   }
   return 0;
}

static int
migrate_pgbackrest(char* source_dir, char* backup_id, char* server, char* workspace)
{
   char* target_dir = NULL;
   // struct muse_configuration* config = NULL;

   // config = (struct muse_configuration*)shmem;
   pgmoneta_log_info("Start migration from pgBackRest, workspace %s", workspace);

   build_target_dir(source_dir, server, &target_dir);
   pgmoneta_log_info("Creating backup directory %s", target_dir);
   if (pgmoneta_mkdir(target_dir))
   {
      pgmoneta_log_error("Failed to create target directory at %s", target_dir);
      goto error;
   }
   if (decrypt_backup_info(source_dir, workspace))
   {
      pgmoneta_log_error("Failed to decrypt backup info");
   }

   free(target_dir);
   return 0;

error:
   pgmoneta_delete_directory(target_dir);
   free(target_dir);
   return 1;
}

static int
decrypt_backup_info(char* source_dir, char* workspace)
{
   char* backup_info_path = NULL;
   char* dest = NULL;
   size_t cipher_len = 0;
   struct muse_configuration* conf = NULL;

   conf = (struct muse_configuration*)shmem;

   backup_info_path = pgmoneta_append(backup_info_path, source_dir);
   backup_info_path = pgmoneta_append(backup_info_path, PGBACKREST_BACKUP_INFO);
   dest = pgmoneta_append(dest, workspace);
   dest = pgmoneta_append(dest, PGBACKREST_BACKUP_INFO);

   cipher_len = strlen(conf->source_cipher);

   pgmoneta_log_info("Decrypting backup info from %s to %s", backup_info_path, dest);
   if (pgmoneta_cbc_decrypt_salted_file(CBC_DIGEST_DEFAULT,
                                        false,
                                        (unsigned char*)conf->source_cipher,
                                        cipher_len,
                                        backup_info_path,
                                        dest))
   {
      pgmoneta_log_error("Failed to decrypt backup info at %s", backup_info_path);
      goto error;
   }

   free(dest);
   free(backup_info_path);
   return 0;
error:
   free(dest);
   free(backup_info_path);
   return 1;
}

static void
build_target_dir(char* source_dir, char* server, char** target_dir)
{
   char* dir = NULL;
   *target_dir = NULL;

   dir = pgmoneta_append(dir, source_dir);
   dir = pgmoneta_append(dir, server);
   dir = pgmoneta_append(dir, "/");
   *target_dir = dir;
}

static int
pgbackrest_backup_info_create(char* backup_id, struct json* info, struct pgbackrest_backup_info** backup)
{
   struct pgbackrest_backup_info* b = NULL;
   struct json_iterator* iter = NULL;
   struct json* backup_chain = NULL;
   char* type = NULL;
   int idx = 0;

   if (info == NULL || info->type != JSONItem)
   {
      pgmoneta_log_error("Incorrect backup info type");
      goto error;
   }

   b = malloc(sizeof(struct pgbackrest_backup_info));
   memset(b, 0, sizeof(struct pgbackrest_backup_info));
   b->archive_start = pgmoneta_append(b->archive_start, (char*)pgmoneta_json_get(info, "backup-archive-start"));
   b->archive_stop = pgmoneta_append(b->archive_stop, (char*)pgmoneta_json_get(info, "backup-archive-stop"));
   b->lsn_start = pgmoneta_append(b->lsn_start, (char*)pgmoneta_json_get(info, "backup-lsn-start"));
   b->lsn_stop = pgmoneta_append(b->lsn_stop, (char*)pgmoneta_json_get(info, "backup-lsn-stop"));
   b->restore_size = (size_t)pgmoneta_json_get(info, "backup-info-size");
   b->start_time = (time_t)pgmoneta_json_get(info, "backup-timestamp-start");
   assert(b->restore_size != 0 && b->start_time != 0);

   type = (char*)pgmoneta_json_get(info, "backup-type");
   if (pgmoneta_compare_string(type, "full"))
   {
      b->type = TYPE_FULL;
   }
   else if (pgmoneta_compare_string(type, "incr"))
   {
      b->type = TYPE_INCREMENTAL;
   }
   else if (pgmoneta_compare_string(type, "diff"))
   {
      b->type = TYPE_DIFFERENTIAL;
   }
   else
   {
      pgmoneta_log_error("unrecognized backup type %s, backup id %s", type, backup_id);
      goto error;
   }

   b->backup_id = pgmoneta_append(b->backup_id, backup_id);
   if (pgmoneta_json_contains_key(info, "backup-prior"))
   {
      b->backup_parent = pgmoneta_append(b->backup_parent, (char*)pgmoneta_json_get(info, "backup-prior"));

      backup_chain = pgmoneta_json_get(info, "backup-reference");

      if (backup_chain == NULL || backup_chain->type != JSONArray)
      {
         pgmoneta_log_error("Incorrect backup reference type");
         goto error;
      }

      b->backup_chain_size = pgmoneta_json_array_length(backup_chain);
      b->backup_chain = malloc(sizeof(char*) * b->backup_chain_size);
      memset(b->backup_chain, 0, sizeof(sizeof(char*) * b->backup_chain_size));
      pgmoneta_json_iterator_create(backup_chain, &iter);
      while (pgmoneta_json_iterator_next(iter))
      {
         b->backup_chain[idx] = pgmoneta_append(b->backup_chain[idx], (char*)iter->value->data);
         idx++;
      }
      assert(idx == b->backup_chain_size);
   }
   pgmoneta_json_iterator_destroy(iter);
   *backup = b;

   return 0;

error:
   pgbackrest_backup_info_destroy(b);
   pgmoneta_json_iterator_destroy(iter);
   return 1;
}

static void
pgbackrest_backup_info_destroy(struct pgbackrest_backup_info* backup)
{
   free(backup->lsn_start);
   free(backup->lsn_stop);
   free(backup->archive_start);
   free(backup->archive_stop);
   for (int i = 0; i < backup->backup_chain_size; i++)
   {
      free(backup->backup_chain[i]);
   }
   free(backup->backup_chain);
   free(backup->backup_parent);
   free(backup);
}

static void
pgbackrest_backup_info_destroy_cb(uintptr_t data)
{
   pgbackrest_backup_info_destroy((struct pgbackrest_backup_info*)data);
   return 0;
}