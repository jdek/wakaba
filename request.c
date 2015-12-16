#include "sfh.h"

static void gen_post_response(char *buf, size_t len, struct request *r)
{
	if (!r->ext[0]) snprintf(buf, len, "%s/%llx\n", config->domainname, r->id);
	else snprintf(buf, len, "%s/%llx.%s\n", config->domainname, r->id, r->ext);
}

void process_admincmd(struct client_ctx *cc)
{
	char *cmd = cc->r->filename + 1;

	if (!config->admin_pwd[0]){
		socket_puts(cc, HTTP_200 "Administration disabled (no password set)\n");
		return;
	}

	//Get and verify password.
	char pwd[128];
	char *pwd_delim = strchr(cmd, ':');
	size_t pwd_len = 0;
	if (!pwd_delim){
		socket_puts(cc, HTTP_200 "Password required\n");
		return;
	}
	pwd_len = MIN(pwd_delim - cmd, 127);
	strncpy(pwd, cmd, pwd_len);
	pwd[pwd_len] = 0;

	if(strcmp(config->admin_pwd, pwd)){
		socket_puts(cc, HTTP_200 "Access denied\n");
		wkb_log(LOG_ADMIN, "Incorrect password");
		return;
	}
	cmd = pwd_delim + 1;

	wkb_log(LOG_ADMIN, "Executed command \"%s\"", cmd);

	char *err_inv = "Invalid syntax\n";

	//Process command.
	if (strstr(cmd, "stats") == cmd){ //Print stats.
		struct db_stats stats;
		memset(&stats, 0, sizeof(stats));
		char buf[1024];

		database_getstats(&stats);
		snprintf(buf, 1024,
				HTTP_200
				"Disk: %.2f/%.2f MB\n"
				"Cache: %.2f/%.2f MB\n"
				"Files: %zu (%zu cached)\n",
				(float) stats.disk_use / 1000000.0, (float) stats.disk_max / 1000000.0,
				(float) stats.cache_use / 1000000.0, (float) stats.cache_max / 1000000.0,
				stats.files, stats.cache_entries
		);
		socket_puts(cc, buf);
	}else if (strstr(cmd, "shutdown") == cmd){ //Shutdown server.
		socket_puts(cc, HTTP_200 "Shutting down server\n");
		kill(getpid(), SIGTERM);
	}else if (strstr(cmd, "rm") == cmd){ //Remove file.
		char *name = strchr(cmd, '=');
		if (!name){
			socket_puts(cc, HTTP_200);
			socket_puts(cc, err_inv);
			return;
		}
		name++;

		if (database_rm(name)){
			socket_puts(cc, HTTP_200 "File not found in database\n");
			return;
		}
		socket_puts(cc, "File removed from database\n");
	}else{ //Print help.
		socket_puts(cc,
				HTTP_200
				"Available commands:\n"
				"stats - print database statistics\n"
				"shutdown - gracefully terminate server\n"
				"rm - remove file from database\n"
		);
	}
}

void *process_request(void *p)
{
	char *err_invreq = "Invalid request\n";
	char *err_toolarge = "File too large\n";
	char *err_nodata = "No data received\n";
	char *err_notfound = "File not found in database\n";

	struct client_ctx *cc = p;
	struct request r;

	prctl(PR_SET_NAME, (char *) "Worker thread", 0, 0, 0);

	memset(&r, 0, sizeof(r));
	http_process_request(cc, &r);
	cc->r = &r;

	if (r.type == R_INVALID){
		socket_puts(cc, HTTP_200);
		switch(errno){
			case EFBIG:
				socket_puts(cc, err_toolarge);
				break;
			case ENODATA:
				socket_puts(cc, err_nodata);
				break;
			case EINVAL:
			default:
				socket_puts(cc, err_invreq);
				break;
		}
		errno = 0;
		goto RET;
	}

	if (r.type == R_CMD){
		process_admincmd(cc);
	}else if (r.type == R_POST){
		errno = 0;
		database_push(&r);
		char buf[128];

		socket_puts(cc, HTTP_200);
		if (errno == EEXIST){
			socket_puts(cc, "Duplicate detected, already exists here:\n");
			free(r.data);
		}
		else{
			wkb_log(LOG_REQ, "%s file of %zu bytes uploaded (%llx)", r.ext[0] ? r.ext : "Unknown", r.len, r.id);
		}

		gen_post_response(buf, 128, &r);
		socket_puts(cc, buf);
	}else if (r.type == R_GET){
		database_getfile(&r);
		char http_header[2048];

		if (!r.data){
			socket_puts(cc, HTTP_200);
			socket_puts(cc, err_notfound);
			goto RET;
		}

		wkb_log(LOG_REQ, "File %llx requested (ref: %s)", r.id, r.referer[0] ? r.referer : "none");

		snprintf(http_header, 2048, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\nExpires: Sun, 17-jan-2038 19:14:07 GMT\r\nContent-Disposition: inline; filename=\"%llx.%s\"\r\n\r\n", r.len, r.id, r.ext[0] ? r.ext : "bin");
		socket_puts(cc, http_header);
		socket_write(cc, r.data, r.len);
	}else if (r.type == R_CACHED){
		char *http_header = "HTTP/1.0 304 Not Modified\r\n\r\n";

		database_getfile(&r);
		if (!r.data){
			socket_puts(cc, HTTP_200);
			socket_puts(cc, err_notfound);
			goto RET;
		}

		wkb_log(LOG_REQ, "Browser-cached file %llx requested (ref: %s)", r.id, r.referer[0] ? r.referer : "none");

		socket_puts(cc, http_header);
	}

RET:
	socket_close(cc);
	cc->ts->terminated = 1;
	free(cc);
	pthread_exit(0);
}
