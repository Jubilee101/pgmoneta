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
#include <value.h>

// system
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#define PGBACKREST_BACKUP_INFO     "backup.info"
#define PGBACKREST_BACKUP_MANIFEST "backup.manifest"
#define CBC_DIGEST_DEFAULT         "sha1"
#define BACKUP_ID_SIZE             14

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

static int load_backup_info(char* source_dir, char* workspace, char** cipher, struct art** backup_info);
static void build_target_dir(char* source_dir, char* server, char** target_dir);
static int migrate_pgbackrest(char* source_dir, char* backup_id, char* server, char* workspace);

static int parse_pgbackrest_backup_info(char* path, char** cipher, struct art** backups);
static int insert_pgbackrest_backup_info(char* backup_id, struct pgbackrest_backup_info* backup, struct art* backups);
static int pgbackrest_backup_info_create(char* backup_id, struct json* info, struct pgbackrest_backup_info** backup);
static void pgbackrest_backup_info_destroy(struct pgbackrest_backup_info* backup);
static void pgbackrest_backup_info_destroy_cb(uintptr_t data);
static void get_target_backup_id(time_t start_time, char** target_id);
static int migrate_pgbackrest_backup(struct pgbackrest_backup_info* backup_info, char* cipher, char* root_workspace, char* source_dir, char* target_dir);
static int decrypt_pgbackrest_manifest(char* cipher, char* source_backup_path, char* workspace);

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
   char* cipher = NULL;
   struct art* backups = NULL;
   struct pgbackrest_backup_info* bck = NULL;
   // struct muse_configuration* config = NULL;

   // config = (struct muse_configuration*)shmem;
   pgmoneta_log_info("Start migration from pgBackRest, workspace %s", workspace);

   build_target_dir(source_dir, server, &target_dir);
   if (pgmoneta_exists(target_dir))
   {
      if (pgmoneta_delete_directory(target_dir))
      {
         pgmoneta_log_error("Failed to clean up target directory %s", target_dir);
      }
   }
   pgmoneta_log_info("Creating backup directory %s", target_dir);
   if (pgmoneta_mkdir(target_dir))
   {
      pgmoneta_log_error("Failed to create target directory at %s", target_dir);
      goto error;
   }
   if (load_backup_info(source_dir, workspace, &cipher, &backups))
   {
      pgmoneta_log_error("Failed to load backup info");
   }

   bck = (struct pgbackrest_backup_info*)pgmoneta_art_search(backups, backup_id);
   if (bck == NULL)
   {
      pgmoneta_log_error("Unable to find backup info of %s", backup_id);
      goto error;
   }
   else
   {
      pgmoneta_log_info("Found backup info of %s, backup start time %lld", backup_id, bck->start_time);
   }

   if (migrate_pgbackrest_backup(bck, cipher, workspace, source_dir, target_dir))
   {
      pgmoneta_log_error("Failed to migrate backup %s", bck->backup_id);
      goto error;
   }

   for (int i = 0; i < bck->backup_chain_size; i++)
   {
      char* parent_backup_id = bck->backup_chain[i];
      struct pgbackrest_backup_info* b = (struct pgbackrest_backup_info*)pgmoneta_art_search(backups, parent_backup_id);
      if (b == NULL)
      {
         pgmoneta_log_error("Failed to find parent backup %s", parent_backup_id);
         goto error;
      }
      if (migrate_pgbackrest_backup(b, cipher, workspace, source_dir, target_dir))
      {
         pgmoneta_log_error("Failed to migrate backup %s", b->backup_id);
         goto error;
      }
   }

   free(cipher);
   free(target_dir);
   pgmoneta_art_destroy(backups);
   return 0;

error:
   pgmoneta_delete_directory(target_dir);
   free(target_dir);
   free(cipher);
   pgmoneta_art_destroy(backups);
   return 1;
}

static int
load_backup_info(char* source_dir, char* workspace, char** cipher, struct art** backups)
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

   // TODO: handle the case where backup is not encrypted
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

   if (parse_pgbackrest_backup_info(dest, cipher, backups))
   {
      pgmoneta_log_error("Failed to parse backup info at %s", dest);
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
   dir = pgmoneta_append(dir, "/backup/");
   *target_dir = dir;
}

static int
parse_pgbackrest_backup_info(char* path, char** cipher, struct art** backups)
{
   struct art* dict = NULL;
   struct json* backup_data = NULL;
   struct pgbackrest_backup_info* bck = NULL;
   char* ciph = NULL;
   char buffer[INFO_BUFFER_SIZE];
   FILE* file = NULL;
   bool is_backup_section = false;

   *cipher = NULL;
   *backups = NULL;

   pgmoneta_art_create(&dict);

   if (pgmoneta_exists(path))
   {
      file = fopen(path, "r");
      if (file == NULL)
      {
         pgmoneta_log_error("Could not open file %s due to %s", path, strerror(errno));
         errno = 0;
         goto error;
      }
   }

   if (file != NULL)
   {
      while ((fgets(&buffer[0], sizeof(buffer), file)) != NULL)
      {
         char key[INFO_BUFFER_SIZE];
         char value[INFO_BUFFER_SIZE];
         char* ptr = NULL;

         if (buffer[0] == '\n')
         {
            continue;
         }

         if (pgmoneta_starts_with(buffer, "["))
         {
            if (pgmoneta_starts_with(buffer, "[backup:current]"))
            {
               is_backup_section = true;
            }
            else if (is_backup_section)
            {
               is_backup_section = false;
            }
            continue;
         }

         memset(&key[0], 0, sizeof(key));
         memset(&value[0], 0, sizeof(value));

         ptr = strtok(&buffer[0], "=");

         if (ptr == NULL)
         {
            goto error;
         }

         memcpy(&key[0], ptr, strlen(ptr));

         ptr = strtok(NULL, "=");

         if (ptr == NULL)
         {
            goto error;
         }

         memcpy(&value[0], ptr, strlen(ptr) - 1);

         if (is_backup_section)
         {
            if (pgmoneta_json_parse_string(value, &backup_data))
            {
               pgmoneta_log_error("unable to parse backup info %s", value);
               goto error;
            }
            if (pgbackrest_backup_info_create(key, backup_data, &bck))
            {
               pgmoneta_log_error("unable to create backup info %s", key);
               goto error;
            }
            if (insert_pgbackrest_backup_info(key, bck, dict))
            {
               pgmoneta_log_error("unable to insert backup info");
               goto error;
            }
            bck = NULL;
            pgmoneta_json_destroy(backup_data);
            backup_data = NULL;
         }
         else if (pgmoneta_compare_string("cipher-pass", &key[0]))
         {
            ciph = pgmoneta_append(ciph, value);
         }
      }
   }

   if (file != NULL)
   {
      fclose(file);
   }

   *cipher = ciph;
   *backups = dict;
   return 0;

error:

   if (file != NULL)
   {
      fclose(file);
   }

   free(ciph);
   pgmoneta_art_destroy(dict);
   pgmoneta_json_destroy(backup_data);
   pgbackrest_backup_info_destroy(bck);
   return 1;
}

static int
insert_pgbackrest_backup_info(char* backup_id, struct pgbackrest_backup_info* backup, struct art* backups)
{
   struct value_config vc = {.destroy_data = &pgbackrest_backup_info_destroy_cb,
                             .to_string = NULL};
   return pgmoneta_art_insert_with_config(backups, backup_id, (uintptr_t)backup, &vc);
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
   *backup = NULL;

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

      backup_chain = (struct json*)pgmoneta_json_get(info, "backup-reference");

      if (backup_chain == NULL || backup_chain->type != JSONArray)
      {
         pgmoneta_log_error("Incorrect backup reference type");
         goto error;
      }

      b->backup_chain_size = pgmoneta_json_array_length(backup_chain);
      b->backup_chain = malloc(sizeof(char*) * b->backup_chain_size);
      memset(b->backup_chain, 0, sizeof(char*) * b->backup_chain_size);
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
   if (backup == NULL)
   {
      return;
   }
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
}

static void
get_target_backup_id(time_t start_time, char** target_id)
{
   char* id = NULL;
   struct tm* time_info = localtime(&start_time);
   *target_id = NULL;

   id = (char*)malloc(BACKUP_ID_SIZE + 1);
   memset(id, 0, BACKUP_ID_SIZE + 1);
   strftime(id, BACKUP_ID_SIZE, "%Y%m%d%H%M%S", time_info);
   *target_id = id;
}

static int
migrate_pgbackrest_backup(struct pgbackrest_backup_info* backup_info, char* cipher, char* root_workspace, char* source_dir, char* target_dir)
{
   char* target_backup_id = NULL;
   char source_backup_path[MAX_PATH];
   char target_backup_path[MAX_PATH];
   char workspace[MAX_PATH];
   memset(target_backup_path, 0, sizeof(target_backup_path));
   memset(source_backup_path, 0, sizeof(source_backup_path));
   memset(workspace, 0, sizeof(workspace));

   get_target_backup_id(backup_info->start_time, &target_backup_id);
   snprintf(source_backup_path, sizeof(source_backup_path), "%s%s/", source_dir, backup_info->backup_id);
   snprintf(target_backup_path, sizeof(target_backup_path), "%s%s/", target_dir, target_backup_id);
   snprintf(workspace, sizeof(workspace), "%s%s/", root_workspace, backup_info->backup_id);

   pgmoneta_log_info("Start to migrate backup %s from %s to %s", backup_info->backup_id, source_backup_path, target_backup_path);

   if (pgmoneta_mkdir(workspace))
   {
      pgmoneta_log_error("Failed to create workspace directory %s", workspace);
      goto error;
   }

   if (pgmoneta_mkdir(target_backup_path))
   {
      pgmoneta_log_error("Failed to create backup directory %s", target_backup_path);
      goto error;
   }
   //TODO: handle the case where backup is not encrypted
   if (decrypt_pgbackrest_manifest(cipher, source_backup_path, workspace))
   {
      pgmoneta_log_error("Failed to decrypt backup manifest %s%s", source_backup_path, PGBACKREST_BACKUP_MANIFEST);
      goto error;
   }
   free(target_backup_id);
   return 0;
error:
   free(target_backup_id);
   return 1;
}

static int
decrypt_pgbackrest_manifest(char* cipher, char* source_backup_path, char* workspace)
{
   char manifest_path[MAX_PATH];
   char dest[MAX_PATH];
   memset(manifest_path, 0, sizeof(manifest_path));
   memset(dest, 0, sizeof(dest));
   snprintf(manifest_path, sizeof(manifest_path), "%s%s", source_backup_path, PGBACKREST_BACKUP_MANIFEST);
   snprintf(dest, sizeof(dest), "%s%s", workspace, PGBACKREST_BACKUP_MANIFEST);
   pgmoneta_log_info("decrypting %s to %s", manifest_path, dest);
   return pgmoneta_cbc_decrypt_salted_file(CBC_DIGEST_DEFAULT,
                                           false,
                                           (unsigned char*)cipher,
                                           strlen(cipher),
                                           manifest_path,
                                           dest);
}