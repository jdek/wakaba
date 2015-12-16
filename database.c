#include "sfh.h"

struct file_entry{
	char *data; // Cached data.
	size_t len; // Data length.
	unsigned long long id; // 64bit ID.
	char hash[HASH_STRLEN]; // File hash.
	char ext[32]; // File extension.
	time_t last_access; // Last acccess time.
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long next_id;
static struct lnode *file_list;

#define serialize_id(ID, BUF, LEN) {snprintf(BUF, LEN, DATA_DIR "database/%llx", ID);}

int isonfs(unsigned long long id)
{
	char name[256];
	serialize_id(id, name, 256);

	struct stat s;
	return (stat(name, &s) == 0);
}

int database_write(struct file_entry *fe)
{
	char name[256];
	serialize_id(fe->id, name, 256);

	FILE *fp = fopen(name, "wb");
	if (!fp)
		return 1;

	fwrite(fe->data, 1, fe->len, fp);
	fe->last_access = time(0);

	fclose(fp);
	return 0;
}

void database_read(struct file_entry *fe)
{
	fe->last_access = time(0);

	// Check first that the file is present on disk before using the cache.
	if (!isonfs(fe->id)){
		if (fe->data) free(fe->data);
		fe->data = 0;
		return;
	}

	// Only read if isn't already cached.
	if (fe->data) return;

	char name[256];
	serialize_id(fe->id, name, 256);

	FILE *fp = fopen(name, "rb");
	if (!fp){
		fe->data = 0;
		return;
	}

	if (fe->len == 0){
		fseek(fp, 0, SEEK_END);
		fe->len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
	}

	fe->data = malloc(fe->len);
	fread(fe->data, 1, fe->len, fp);

	fclose(fp);
}

void printhash(unsigned char *hash, char *buf)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		buf += sprintf(buf, "%02x", hash[i]);
	}

	buf[0] = 0;
}

void hash(char *data, size_t len, char *buf)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	SHA256_Update(&ctx, data, len);
	SHA256_Final(hash, &ctx);

	printhash(hash, buf);
}

char exists(char *hash, unsigned long long *id)
{
	pthread_mutex_lock(&lock);
	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		if (!strcmp(fe->hash, hash)){
			if (id)
				*id = fe->id;
			pthread_mutex_unlock(&lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&lock);

	return 0;
}

void database_push(struct request *r)
{
	struct lnode *n = calloc(sizeof(struct lnode), 1);
	struct file_entry *fe = calloc(sizeof(struct file_entry), 1);

	hash(r->data, r->len, fe->hash);
	unsigned long long id = 0;
	if (exists(fe->hash, &id)){
		free(fe);
		free(n);
		errno = EEXIST;
		r->id = id;
		return;
	}

	fe->data = r->data;
	fe->len = r->len;
	fe->id = next_id++;
	strcpy(fe->ext, r->ext);
	n->data = fe;

	pthread_mutex_lock(&lock);
	file_list = lnode_push(file_list, n);
	pthread_mutex_unlock(&lock);

	database_write(fe);

	r->id = fe->id;
	return;
}

struct lnode *database_get(unsigned long long id)
{
	pthread_mutex_lock(&lock);

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		if (fe->id == id){
			pthread_mutex_unlock(&lock);
			return cur;
		}
	}

	pthread_mutex_unlock(&lock);
	return 0;
}

void database_pop(struct lnode *node)
{
	pthread_mutex_lock(&lock);

	free(node->data);
	if (node == file_list)
		file_list = file_list->next;
	free(lnode_pop(node));

	pthread_mutex_unlock(&lock);
}

static void database_uncache(struct file_entry *fe)
{
	free(fe->data);
	fe->data = 0;
}

int database_rm(char *name)
{
	unsigned long long id = strtoull(name, 0, 16);
	struct lnode *node = database_get(id);

	if (!node)
		return 1;

	database_uncache(node->data);
	database_pop(node);

	char buf[512];
	snprintf(buf, 512, DATA_DIR "/database/%llx", id);
	remove(buf);

	wkb_log(LOG_DB, "File %llx removed", id);

	return 0;
}

void database_getfile(struct request *r)
{
	struct file_entry *entry = 0;
	char *err = 0;
	unsigned long long id = strtoull(r->filename, &err, 16);
	if ((!id && errno == EINVAL) || (err && *err)){
		errno = 0;
		r->data = 0;
		return;
	}

	struct lnode *n = database_get(id);

	if (n){
		entry = n->data;
		database_read(entry);

		// For some reason we couldn't load the file from disk.
		// Unlink node from list and return.
		if (!entry->data){
			wkb_log(LOG_DB, "File %llx not found on disk, unlinking", entry->id);
			r->data = 0;
			database_pop(n);
			return;
		}

		r->data = entry->data;
		r->len = entry->len;
		r->id = id;
		strcpy(r->ext, entry->ext);
		return;
	}

	r->data = 0;
}

int database_init()
{
	if (!config->db_persist)
		return 0;

	FILE *fp = fopen(DATA_DIR "/database.txt", "r");

	if (!fp){ //Generate database.txt from contents on FS.
		fp = fopen(DATA_DIR "/database.txt", "w");
		DIR *dp = opendir(DATA_DIR "/database/");
		struct dirent *ent = 0;
		if (!dp){
			fclose(fp);
			return 1;
		}

		while ((ent = readdir(dp))){
			if (ent->d_name[0] == '.' || ent->d_type == DT_DIR)
				continue;

			struct file_entry fe;
			char *end = 0;

			fe.id = strtoull(ent->d_name, &end, 16);
			if (end && *end)
				continue;
			fe.len = 0; //Will be filled in by database_read.
			database_read(&fe);
			hash(fe.data, fe.len, fe.hash);

			fprintf(fp, "%llx %zu NULL %s\n", fe.id, fe.len, fe.hash);
			free(fe.data);
		}

		closedir(dp);
		fclose(fp);
		fp = fopen(DATA_DIR "/database.txt", "r");
	}

	while(!feof(fp)){
		struct lnode *n = calloc(sizeof(struct lnode), 1);
		struct file_entry *fe = calloc(sizeof(struct file_entry), 1);
		fscanf(fp, "%llx %zu %s %s\n", &fe->id, &fe->len, fe->ext, fe->hash);

		if (fe->len == 0 || !isonfs(fe->id)){ //Not a valid entry.
			wkb_log(LOG_DB, "%llx: Invalid entry, ignoring", fe->id);
			free(n);
			free(fe);
			continue;
		}

		if (!strcmp(fe->ext, "NULL")){ // File has no extension.
			fe->ext[0] = 0;
		}

		if (!strcmp(fe->hash, "0")){ //File has no hash, generate one.
			database_read(fe);
			hash(fe->data, fe->len, fe->hash);
			free(fe->data);
		}

		if (exists(fe->hash, 0)){ //Check if file is already in DB.
			wkb_log(LOG_DB, "%llx: Duplicate detected, removing and continuing", fe->id);
			char buf[512];
			snprintf(buf, 512, DATA_DIR "/database/%llx", fe->id);
			remove(buf);
			free(n);
			free(fe);
			continue;
		}

		n->data = fe;
		file_list = lnode_push(file_list, n);
		if (fe->id >= next_id)
			next_id = fe->id + 1;
	}
	fclose(fp);

	return 0;
}

void database_destroydb()
{
	if (config->db_persist)
		return;

	char name[256];

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		serialize_id(fe->id, name, 256);
		remove(name);
	}
}

int database_flush()
{
	if (!config->db_persist)
		return 0;

	pthread_mutex_lock(&lock);
	FILE *fp = fopen(DATA_DIR "/database.txt", "w");
	if (!fp)
		return 1;

	for (struct lnode *cur = listend(file_list); cur; cur = cur->prev){
		struct file_entry *fe = cur->data;
		fprintf(fp, "%llx %zu %s %s\n", fe->id, fe->len, fe->ext[0] ? fe->ext : "NULL", fe->hash);
	}

	fclose(fp);
	pthread_mutex_unlock(&lock);
	return 0;
}

void database_terminate()
{
	database_flush();
	database_destroydb();

	pthread_mutex_lock(&lock);
	struct lnode *cur = file_list;
	while (cur){
		struct lnode *temp = cur;
		struct file_entry *fe = cur->data;

		cur = cur->next;

		database_uncache(fe);
		free(fe);
		free(temp);
	}
}

int database_getstats(struct db_stats *stats)
{
	struct statvfs vfs;
	if (statvfs(DATA_DIR "/database/", &vfs))
		return 1;

	pthread_mutex_lock(&lock);
	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		stats->files++;
		stats->disk_use += fe->len;
		if (fe->data){
			stats->cache_entries++;
			stats->cache_use += fe->len;
		}
	}
	pthread_mutex_unlock(&lock);

	stats->disk_max = (vfs.f_bsize * vfs.f_bfree) + stats->disk_use;
	stats->cache_max = config->max_cache_size;

	return 0;
}

void cache_prune()
{
	size_t freed = 0; // Bytes freed.
	size_t pruned = 0; // Files freed.

	pthread_mutex_lock(&lock);

	// Keep pruning the oldest cached object until max_cache_size is satisfied.
	while (1){
		struct file_entry *oldest = 0;
		size_t size = 0;

		for (struct lnode *cur = file_list; cur; cur = cur->next){
			struct file_entry *fe = cur->data;

			if (fe->data){
				if (!oldest || fe->last_access < oldest->last_access)
					oldest = fe;

				size += fe->len;
			}
		}

		if (oldest && size >= config->max_cache_size){
			database_uncache(oldest);
			freed += oldest->len;
			pruned += 1;
			continue;
		}
		break;
	}

	pthread_mutex_unlock(&lock);

	if (pruned)
		wkb_log(LOG_CACHE, "Pruned %zu files (%zu bytes)", pruned, freed);
}
