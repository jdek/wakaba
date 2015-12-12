#include "sfh.h"

char *http_get_field(char *buf, char *name)
{
	char *attr = 0;
	char *val = 0;

	attr = strcasestr(buf, name);
	if (!attr) return 0;

	val = strchr(attr, ':');
	if (!val) return 0;

	val++;
	if (isspace(*val)) val = strprint(val);

	return val;
}

size_t http_get_header(char *buf, char *header, size_t n)
{
	char *end = strstr(buf, "\r\n\r\n");
	size_t len = 0;

	if (!end)
		return 0;
	end += 4;

	len = MIN((size_t) (end - buf), n - 1);
	memcpy(header, buf, len);
	header[len] = 0;

	return len;
}

void http_process_request(struct client_ctx *cc, struct request *r)
{
	char *buf = calloc(2048, 1);
	size_t buf_len = 0;

	buf_len = socket_gets(cc, buf, 2047);
	if (buf_len <= 0){
		errno = ENODATA;
		goto ERROR;
	}
	buf[buf_len] = 0;

	if (strstr(buf, "GET") == buf){
		r->type = R_GET;
	}else if (strstr(buf, "POST") == buf){
		r->type = R_POST;
	}else{
		errno = EINVAL;
		goto ERROR;
	}

	if (r->type == R_POST){
		char header[2048];
		char boundary[256];
		size_t header_len = 0;
		size_t content_length = 0; //Length as reported by HTTP header.

		//Some (retarded) browsers (like Firefox) like to send the body in the same packet as the header, so:
		//Move header into it's own buffer, and move body to front of buf.
		memset(header, 0, 2048);
		header_len = http_get_header(buf, header, 2048);
		if (!header_len){
			errno = EINVAL;
			goto ERROR;
		}
		buf_len -= header_len;
		memmove(buf, buf + header_len, buf_len);

		//Make sure header sends Content-Length.
		char *clf = http_get_field(header, "Content-Length:");
		if (clf) content_length = strtol(clf, 0, 10);
		if (!clf || !content_length){
			errno = EINVAL;
			goto ERROR;
		}

		//Make sure encoding is multipart/form-data and extract the boundary.
		size_t b_len = 0;
		char *bp = http_get_field(header, "Content-Type: multipart/form-data; boundary=");
		if (!bp){
			errno = EINVAL;
			goto ERROR;
		}
		bp = strchr(bp, '=') + 1;
		b_len = MIN(strchr(bp, '\r') - bp, 255);
		strncpy(boundary, bp, b_len);
		boundary[b_len] = 0;

		//Send 100-continue if needed.
		if (strcasestr(header, "Expect: 100-continue"))
			socket_puts(cc, "HTTP/1.0 100 Continue\r\n\r\n");

		//Expand buf and read in rest of the body.
		buf = realloc(buf, content_length + 1);
		buf_len += socket_read(cc, buf + buf_len, content_length - buf_len);
		buf[buf_len] = 0;

		//I wouldn't trust it, considering most of these requests are coming from /g/.
		if (buf_len != content_length){
			errno = EINVAL;
			goto ERROR;
		}

		//Form parsing starts here.
		char *start = 0;
		char *end = 0;
		size_t file_len = 0;

		// Get filename extension if provided.
		start = strstr(buf, "filename=\"");
		if (start && strstr(buf, "\r\n\r\n") > start){
			// Just re-using variables.
			// Honestly i should just start lexing this shit because this is ugly as all hell.
			start = strchr(start, '"');
			end = strchr(++start, '"');
			if (!end){
				errno = EINVAL;
				goto ERROR;
			}
			file_len = end - start;
			char name[file_len + 1];
			strncpy(name, start, file_len);
			name[file_len] = 0;
			start = strrchr(name + 1, '.');
			if (start){
				start += 1;
				file_len = MIN(strlen(start), 31);
				strncpy(r->ext, start, file_len);
				r->ext[file_len] = 0;
			}
		}

		//Skip header information.
		start = strstr(buf, "\r\n\r\n");
		if (!start){
			errno = EINVAL;
			goto ERROR;
		}
		start += 4;

		end = memmem(start, buf_len - (start - buf), boundary, strlen(boundary));
		if (!end){
			errno = EINVAL;
			goto ERROR;
		}
		end -= 4;
		file_len = end - start;

		if (file_len <= 0){
			errno = ENODATA;
			goto ERROR;
		}

		//Let's reuse buf by memmove'ing the file data to the beginning.
		memmove(buf, start, file_len);
		buf = realloc(buf, file_len);
		buf_len = file_len;

		r->len = buf_len;
		r->data = buf;
	}else if (r->type == R_GET){
		//Extract filename.
		char *filename = strchr(buf, '/');
		size_t fn_len = 0;
		if (!filename || (filename - buf) > 4){
			errno = EINVAL;
			goto ERROR;
		}
		filename++;

		fn_len = MIN(strchr(filename, ' ') - filename, 127);
		strncpy(r->filename, filename, fn_len);
		r->filename[fn_len] = 0;

		//Get referer, for non NSA reasons ofcourse, i swear.
		char *ref = http_get_field(buf, "Referer:");
		char *ref_end = 0;
		size_t ref_len = 0;
		if (ref){
			ref_end = strstr(ref, "\r\n");
			if (!ref_end){
				errno = EINVAL;
				goto ERROR;
			}

			ref_len = MIN((ref_end - ref), 255);
			strncpy(r->referer, ref, ref_len + 1);
			r->referer[ref_len] = 0;
		}

		//Check if admin command.
		if (r->filename[0] == '$'){
			free(buf);
			r->type = R_CMD;
			return;
		}

		//Protect against common exploits.
		if (!r->filename[0] || strchr(r->filename, '/') || strstr(r->filename, "..")){
			errno = EINVAL;
			goto ERROR;
		}

		//Check if the client has already cached this file.
		if (config->browser_cache && strcasestr(buf, "Cache-Control:"))
			r->type = R_CACHED;

		free(buf);
	}

	return;
ERROR:
	if (buf && buf != r->data)
		free(buf);
	r->type = R_INVALID;
	return;
}
