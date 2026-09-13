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
#include <compression.h>
#include <info.h>
#include <json.h>
#include <logging.h>
#include <migration.h>
#include <utils.h>
#include <value.h>

// system
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <time.h>

#define PGBACKREST_BACKUP_INFO     "backup.info"
#define PGBACKREST_BACKUP_MANIFEST "backup.manifest"
#define CBC_DIGEST_DEFAULT         "sha1"
#define BACKUP_ID_SIZE             15
#define PG_DATA_PREFIX_LEN         strlen("pg_data/")
#define PGBACKREST_FILE_REFERENCE  "reference"

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

struct pgbackrest_manifest
{
   int compression;
   char* backup_cipher;
   struct art* files;
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
static int migrate_pgbackrest_backup(struct art* backups, struct pgbackrest_backup_info* backup_info, struct art* references, char* cipher, char* root_workspace, char* source_dir, char* target_dir);
static void pgbackrest_manifest_create(struct pgbackrest_manifest** manifest);
static void pgbackrest_manifest_destroy(struct pgbackrest_manifest* manifest);
static int load_pgbackrest_manifest(char* cipher, char* source_backup_path, char* workspace, struct pgbackrest_manifest** manifest);
static int parse_pgbackrest_manifest(char* path, struct pgbackrest_manifest** manifest);
static int migrate_pgbackrest_file(struct art* backups, struct pgbackrest_backup_info* backup_info, struct pgbackrest_manifest* manifest, struct art* references, char* relative_path, char* source_root_dir, char* target_root_dir, char* workspace_root_dir);
static int create_file_directory(char* target_root_dir, char* workspace_root_dir, char* relative_path);
static int insert_backup_file_referrer(char* reference_backup_id, char* relative_path, char* referrer_backup_id, struct art* references);
static char* get_backup_file_referrer(char* reference_backup_id, char* relative_path, struct art* references);
static int create_file_link_placeholder(char* target_dir, char* relative_path, char* reference_backup_id);

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
   struct art* references = NULL;
   struct pgbackrest_backup_info* bck = NULL;
   // struct muse_configuration* config = NULL;

   // config = (struct muse_configuration*)shmem;
   pgmoneta_log_info("Start migration from pgBackRest, workspace %s", workspace);
   pgmoneta_art_create(&references);
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

   for (int i = 0; i < bck->backup_chain_size; i++)
   {
      char* parent_backup_id = bck->backup_chain[i];
      pgmoneta_log_info("Start migrating parent backup %s", parent_backup_id);
      struct pgbackrest_backup_info* b = (struct pgbackrest_backup_info*)pgmoneta_art_search(backups, parent_backup_id);
      if (b == NULL)
      {
         pgmoneta_log_error("Failed to find parent backup %s", parent_backup_id);
         goto error;
      }
      if (migrate_pgbackrest_backup(backups, b, references, cipher, workspace, source_dir, target_dir))
      {
         pgmoneta_log_error("Failed to migrate backup %s", b->backup_id);
         goto error;
      }
      pgmoneta_log_info("Successfully migrated parent backup %s", parent_backup_id);
   }

   pgmoneta_log_info("Start migrating backup %s", bck->backup_id);
   if (migrate_pgbackrest_backup(backups, bck, references, cipher, workspace, source_dir, target_dir))
   {
      pgmoneta_log_error("Failed to migrate backup %s", bck->backup_id);
      goto error;
   }
   pgmoneta_log_info("Successfully migrated backup %s", bck->backup_id);

   free(cipher);
   free(target_dir);
   pgmoneta_art_destroy(references);
   pgmoneta_art_destroy(backups);
   return 0;

error:
   pgmoneta_delete_directory(target_dir);
   free(target_dir);
   free(cipher);
   pgmoneta_art_destroy(references);
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
   char section[128];
   FILE* file = NULL;

   *cipher = NULL;
   *backups = NULL;

   pgmoneta_art_create(&dict);

   file = fopen(path, "r");
   if (file == NULL)
   {
      pgmoneta_log_error("Could not open file %s: %s", path, strerror(errno));
      errno = 0;
      goto error;
   }

   while ((fgets(&buffer[0], sizeof(buffer), file)) != NULL)
   {
      char key[INFO_BUFFER_SIZE];
      char value[INFO_BUFFER_SIZE];
      char* ptr = NULL;

      if (buffer[0] == '\n')
      {
         continue;
      }

      if (buffer[0] == '[')
      {
         memset(section, 0, sizeof(section));
         memcpy(section, buffer, strlen(buffer) - 1);
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

      if (pgmoneta_compare_string(section, "[backup:current]"))
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
         // remove the double quotes
         value[strlen(value) - 1] = 0;
         ciph = pgmoneta_append(ciph, &value[1]);
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
   free(backup->backup_id);
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

   id = (char*)malloc(BACKUP_ID_SIZE);
   memset(id, 0, BACKUP_ID_SIZE);
   strftime(id, BACKUP_ID_SIZE, "%Y%m%d%H%M%S", time_info);
   *target_id = id;
}

static int
migrate_pgbackrest_backup(struct art* backups, struct pgbackrest_backup_info* backup_info, struct art* references, char* cipher, char* root_workspace, char* source_dir, char* target_dir)
{
   char* target_backup_id = NULL;
   char source_backup_path[MAX_PATH];
   char source_backup_data_path[MAX_PATH];
   char target_backup_path[MAX_PATH];
   char target_backup_data_path[MAX_PATH];
   char workspace[MAX_PATH];
   char data_workspace[MAX_PATH];
   struct pgbackrest_manifest* manifest = NULL;
   struct art_iterator* iter = NULL;

   memset(target_backup_path, 0, sizeof(target_backup_path));
   memset(source_backup_path, 0, sizeof(source_backup_path));
   memset(target_backup_data_path, 0, sizeof(target_backup_data_path));
   memset(source_backup_data_path, 0, sizeof(source_backup_data_path));
   memset(workspace, 0, sizeof(workspace));
   memset(data_workspace, 0, sizeof(data_workspace));

   get_target_backup_id(backup_info->start_time, &target_backup_id);
   snprintf(source_backup_path, sizeof(source_backup_path), "%s%s/", source_dir, backup_info->backup_id);
   snprintf(target_backup_path, sizeof(target_backup_path), "%s%s/", target_dir, target_backup_id);
   snprintf(workspace, sizeof(workspace), "%s%s/", root_workspace, backup_info->backup_id);
   snprintf(source_backup_data_path, sizeof(source_backup_data_path), "%s%s/pg_data/", source_dir, backup_info->backup_id);
   snprintf(target_backup_data_path, sizeof(target_backup_data_path), "%s%s/data/", target_dir, target_backup_id);
   snprintf(data_workspace, sizeof(data_workspace), "%s%s/data/", root_workspace, backup_info->backup_id);

   pgmoneta_log_info("Start to migrate backup %s from %s to %s", backup_info->backup_id, source_backup_path, target_backup_path);

   if (pgmoneta_mkdir(workspace))
   {
      pgmoneta_log_error("Failed to create workspace directory %s", workspace);
      goto error;
   }

   if (pgmoneta_exists(target_backup_path))
   {
      pgmoneta_delete_directory(target_backup_path);
   }

   if (pgmoneta_mkdir(target_backup_path))
   {
      pgmoneta_log_error("Failed to create backup directory %s", target_backup_path);
      goto error;
   }

   if (load_pgbackrest_manifest(cipher, source_backup_path, workspace, &manifest))
   {
      pgmoneta_log_error("Failed to load backup manifest %s%s", source_backup_path, PGBACKREST_BACKUP_MANIFEST);
      goto error;
   }

   pgmoneta_art_iterator_create(manifest->files, &iter);
   while (pgmoneta_art_iterator_next(iter))
   {
      if (pgmoneta_starts_with(iter->key, "pg_wal/summaries/"))
      {
         continue;
      }
      if (migrate_pgbackrest_file(backups, backup_info, manifest, references, iter->key, source_backup_data_path, target_backup_data_path, data_workspace))
      {
         goto error;
      }
   }
   pgmoneta_art_iterator_destroy(iter);
   pgbackrest_manifest_destroy(manifest);
   free(target_backup_id);
   return 0;
error:
   pgmoneta_art_iterator_destroy(iter);
   pgbackrest_manifest_destroy(manifest);
   free(target_backup_id);
   return 1;
}

static void
pgbackrest_manifest_create(struct pgbackrest_manifest** manifest)
{
   struct pgbackrest_manifest* m = NULL;
   *manifest = NULL;
   m = malloc(sizeof(struct pgbackrest_backup_info));
   memset(m, 0, sizeof(struct pgbackrest_manifest));
   pgmoneta_art_create(&m->files);
   *manifest = m;
}

static void
pgbackrest_manifest_destroy(struct pgbackrest_manifest* manifest)
{
   if (manifest == NULL)
   {
      return;
   }
   free(manifest->backup_cipher);
   pgmoneta_art_destroy(manifest->files);
   free(manifest);
}

static int
load_pgbackrest_manifest(char* cipher, char* source_backup_path, char* workspace, struct pgbackrest_manifest** manifest)
{
   char manifest_path[MAX_PATH];
   char dest[MAX_PATH];
   struct pgbackrest_manifest* m = NULL;

   *manifest = NULL;

   memset(manifest_path, 0, sizeof(manifest_path));
   memset(dest, 0, sizeof(dest));
   snprintf(manifest_path, sizeof(manifest_path), "%s%s", source_backup_path, PGBACKREST_BACKUP_MANIFEST);
   snprintf(dest, sizeof(dest), "%s%s", workspace, PGBACKREST_BACKUP_MANIFEST);

   //TODO: handle the case where backup is not encrypted
   pgmoneta_log_info("decrypting %s to %s", manifest_path, dest);
   if (pgmoneta_cbc_decrypt_salted_file(CBC_DIGEST_DEFAULT,
                                        false,
                                        (unsigned char*)cipher,
                                        strlen(cipher),
                                        manifest_path,
                                        dest))
   {
      goto error;
   }
   pgmoneta_log_info("parsing manifest %s", dest);
   if (parse_pgbackrest_manifest(dest, &m))
   {
      goto error;
   }
   *manifest = m;

   return 0;
error:
   return 1;
}

static int
parse_pgbackrest_manifest(char* path, struct pgbackrest_manifest** manifest)
{
   struct pgbackrest_manifest* m = NULL;
   FILE* file = NULL;
   char buffer[INFO_BUFFER_SIZE];
   char section[128];
   struct json* file_info = NULL;

   *manifest = NULL;
   pgbackrest_manifest_create(&m);
   file = fopen(path, "r");
   if (file == NULL)
   {
      pgmoneta_log_error("Could not open file %s: %s", path, strerror(errno));
      errno = 0;
      goto error;
   }

   while ((fgets(&buffer[0], sizeof(buffer), file)) != NULL)
   {
      char key[INFO_BUFFER_SIZE];
      char value[INFO_BUFFER_SIZE];
      char* ptr = NULL;

      if (buffer[0] == '\n')
      {
         continue;
      }

      if (buffer[0] == '[')
      {
         memset(section, 0, sizeof(section));
         memcpy(section, buffer, strlen(buffer) - 1);
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

      if (pgmoneta_compare_string(section, "[target:file]"))
      {
         if (pgmoneta_json_parse_string(value, &file_info))
         {
            pgmoneta_log_error("unable to parse backup info %s", value);
            goto error;
         }
         // strip the pg_data/ entry
         pgmoneta_art_insert(m->files, &key[PG_DATA_PREFIX_LEN], (uintptr_t)file_info, ValueJSON);
         file_info = NULL;
      }
      else if (pgmoneta_compare_string("cipher-pass", &key[0]))
      {
         // remove the double quotes
         value[strlen(value) - 1] = 0;
         m->backup_cipher = pgmoneta_append(m->backup_cipher, &value[1]);
      }
      else if (pgmoneta_compare_string("option-compress-type", &key[0]))
      {
         if (pgmoneta_compare_string(value, "\"none\""))
         {
            m->compression = COMPRESSION_NONE;
         }
         else if (pgmoneta_compare_string(value, "\"gz\""))
         {
            m->compression = COMPRESSION_CLIENT_GZIP;
         }
         else if (pgmoneta_compare_string(value, "\"bz2\""))
         {
            m->compression = COMPRESSION_CLIENT_BZIP2;
         }
         else if (pgmoneta_compare_string(value, "\"lz4\""))
         {
            m->compression = COMPRESSION_CLIENT_LZ4;
         }
         else if (pgmoneta_compare_string(value, "\"zst\""))
         {
            m->compression = COMPRESSION_CLIENT_ZSTD;
         }
         else
         {
            pgmoneta_log_error("Unrecognized compression method %s", value);
            goto error;
         }
      }
   }

   if (file != NULL)
   {
      fclose(file);
   }

   *manifest = m;
   return 0;
error:
   if (file != NULL)
   {
      fclose(file);
   }

   pgbackrest_manifest_destroy(m);
   return 1;
}

static int
migrate_pgbackrest_file(struct art* backups, struct pgbackrest_backup_info* backup_info, struct pgbackrest_manifest* manifest, struct art* references, char* relative_path, char* source_root_dir, char* target_root_dir, char* workspace_root_dir)
{
   char* source_file_path = NULL;
   char* target_file_path = NULL;
   char* workspace_file_path = NULL;
   struct json* file_info = NULL;
   char* root_reference_backup = NULL;
   char* latest_referrer_backup = NULL;
   char* target_backup_id = NULL;
   char* root_reference_backup_id = NULL;
   struct pgbackrest_backup_info* root_reference_backup_info = NULL;

   source_file_path = pgmoneta_append(source_file_path, source_root_dir);
   source_file_path = pgmoneta_append(source_file_path, relative_path);
   target_file_path = pgmoneta_append(target_file_path, target_root_dir);
   target_file_path = pgmoneta_append(target_file_path, relative_path);
   workspace_file_path = pgmoneta_append(workspace_file_path, workspace_root_dir);
   workspace_file_path = pgmoneta_append(workspace_file_path, relative_path);
   get_target_backup_id(backup_info->start_time, &target_backup_id);

   switch (manifest->compression)
   {
      case COMPRESSION_CLIENT_GZIP:
         source_file_path = pgmoneta_append(source_file_path, ".gz");
         workspace_file_path = pgmoneta_append(workspace_file_path, ".gz");
         break;
      case COMPRESSION_CLIENT_LZ4:
         source_file_path = pgmoneta_append(source_file_path, ".lz4");
         workspace_file_path = pgmoneta_append(workspace_file_path, ".lz4");
         break;
      case COMPRESSION_CLIENT_ZSTD:
         source_file_path = pgmoneta_append(source_file_path, ".zst");
         workspace_file_path = pgmoneta_append(workspace_file_path, ".zst");
         break;
      case COMPRESSION_CLIENT_BZIP2:
         source_file_path = pgmoneta_append(source_file_path, ".bz2");
         workspace_file_path = pgmoneta_append(workspace_file_path, ".bz2");
         break;
      default:
         break;
   }

   file_info = (struct json*)pgmoneta_art_search(manifest->files, relative_path);
   if (file_info == NULL)
   {
      pgmoneta_log_error("Unable to find %s in the manifest", relative_path);
      goto error;
   }

   if (create_file_directory(target_root_dir, workspace_root_dir, relative_path))
   {
      pgmoneta_log_error("Failed to create directory for file %s: %s", target_file_path, strerror(errno));
      errno = 0;
      goto error;
   }

   if (!pgmoneta_json_contains_key(file_info, PGBACKREST_FILE_REFERENCE))
   {
      // full file, decrypt and copy to workspace first
      // TODO: handle non encrypted case
      if (pgmoneta_cbc_decrypt_salted_file(CBC_DIGEST_DEFAULT,
                                           false,
                                           (unsigned char*)manifest->backup_cipher,
                                           strlen(manifest->backup_cipher),
                                           source_file_path,
                                           workspace_file_path))
      {
         pgmoneta_log_error("Failed to decrypt %s to %s", source_file_path, target_file_path);
         goto error;
      }
      if (pgmoneta_decompress_file(workspace_file_path, target_file_path, manifest->compression, NULL))
      {
         pgmoneta_log_error("Failed to decompress %s -> %s", workspace_file_path, target_file_path);
         goto error;
      }
   }
   else
   {
      root_reference_backup = (char*)pgmoneta_json_get(file_info, PGBACKREST_FILE_REFERENCE);
      if (root_reference_backup == NULL)
      {
         pgmoneta_log_error("Failed to get reference backup from manifest entry %s", relative_path);
         goto error;
      }

      latest_referrer_backup = get_backup_file_referrer(root_reference_backup, relative_path, references);
      if (latest_referrer_backup == NULL)
      {
         root_reference_backup_info = (struct pgbackrest_backup_info*)pgmoneta_art_search(backups, root_reference_backup);
         if (root_reference_backup_info == NULL)
         {
            pgmoneta_log_error("Failed to find referenced backup %s", root_reference_backup);
            goto error;
         }
         get_target_backup_id(root_reference_backup_info->start_time, &root_reference_backup_id);
         if (create_file_link_placeholder(target_root_dir, relative_path, root_reference_backup_id))
         {
            pgmoneta_log_error("Failed to create placeholder for file %s referencing %s", relative_path, root_reference_backup);
            goto error;
         }
      }
      else
      {
         if (create_file_link_placeholder(target_root_dir, relative_path, latest_referrer_backup))
         {
            pgmoneta_log_error("Failed to create placeholder for file %s referencing %s", relative_path, latest_referrer_backup);
            goto error;
         }
      }
      if (insert_backup_file_referrer(root_reference_backup, relative_path, target_backup_id, references))
      {
         pgmoneta_log_error("Failed to insert latest reference record for file %s referencing %s", relative_path, root_reference_backup);
         goto error;
      }
   }

   free(source_file_path);
   free(target_file_path);
   free(workspace_file_path);
   free(target_backup_id);
   free(root_reference_backup_id);
   return 0;
error:
   free(source_file_path);
   free(target_file_path);
   free(workspace_file_path);
   free(target_backup_id);
   free(root_reference_backup_id);
   return 1;
}

static int
create_file_directory(char* target_root_dir, char* workspace_root_dir, char* relative_path)
{
   char* path = NULL;
   char* workspace_path = NULL;
   path = pgmoneta_append(path, target_root_dir);
   path = pgmoneta_append(path, relative_path);
   workspace_path = pgmoneta_append(workspace_path, workspace_root_dir);
   workspace_path = pgmoneta_append(workspace_path, relative_path);

   char* dir = dirname(path);
   char* wspc_dir = dirname(workspace_path);

   if (!pgmoneta_exists(dir))
   {
      pgmoneta_log_debug("Creating directory for %s", dir);
      if (pgmoneta_mkdir(dir))
      {
         goto error;
      }
   }

   if (!pgmoneta_exists(wspc_dir))
   {
      pgmoneta_log_debug("Creating workspace directory for %s", wspc_dir);
      if (pgmoneta_mkdir(wspc_dir))
      {
         goto error;
      }
   }

   free(path);
   free(workspace_path);
   return 0;
error:
   free(path);
   free(workspace_path);
   return 1;
}

static int
insert_backup_file_referrer(char* reference_backup_id, char* relative_path, char* referrer_backup_id, struct art* references)
{
   char* key = NULL;
   int ret = 0;

   if (references == NULL)
   {
      goto error;
   }

   key = pgmoneta_append(key, reference_backup_id);
   key = pgmoneta_append(key, "_");
   key = pgmoneta_append(key, relative_path);

   ret = pgmoneta_art_insert(references, key, (uintptr_t)referrer_backup_id, ValueString);
   free(key);

   return ret;
error:
   free(key);
   return 1;
}

static char*
get_backup_file_referrer(char* reference_backup_id, char* relative_path, struct art* references)
{
   char* key = NULL;
   char* val = NULL;
   if (references == NULL)
   {
      return NULL;
   }

   key = pgmoneta_append(key, reference_backup_id);
   key = pgmoneta_append(key, "_");
   key = pgmoneta_append(key, relative_path);

   val = (char*)pgmoneta_art_search(references, key);
   free(key);
   return val;
}

static int
create_file_link_placeholder(char* target_dir, char* relative_path, char* reference_backup_id)
{
   char* file_name = NULL;
   char* link_name = NULL;
   char link_path[MAX_PATH];
   FILE* file = NULL;

   memset(link_path, 0, MAX_PATH);

   file_name = strrchr(relative_path, '/');
   if (file_name != NULL)
   {
      file_name++;
   }
   else
   {
      file_name = relative_path;
   }
   link_name = pgmoneta_append(link_name, LINK_PREFIX);
   link_name = pgmoneta_append(link_name, reference_backup_id);
   link_name = pgmoneta_append(link_name, "_");
   link_name = pgmoneta_append(link_name, file_name);

   memcpy(link_path, target_dir, strlen(target_dir));
   memcpy(link_path + strlen(link_path), relative_path, file_name - relative_path);
   memcpy(link_path + strlen(link_path), link_name, strlen(link_name));

   file = fopen(link_path, "w");
   if (file == NULL)
   {
      pgmoneta_log_error("Unable to create link file %s: %s", link_path, strerror(errno));
      errno = 0;
      goto error;
   }
   fclose(file);

   free(link_name);
   return 0;
error:
   if (file != NULL)
   {
      fclose(file);
   }
   free(link_name);
   return 1;
}