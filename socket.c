#include "sfh.h"

struct socket{
	int fd;
	struct sockaddr_un addr;
};

static struct socket srv_http;
static struct socket cli;

void socket_close(struct client_ctx *cc)
{
	shutdown(cc->fd, SHUT_RDWR);
	close(cc->fd);
}

void socket_puts(struct client_ctx *cc, char *str)
{
	write(cc->fd, str, strlen(str));
}

struct client_ctx *socket_listen(struct socket *s)
{
	socklen_t len = sizeof(struct sockaddr_un);
	int fd = accept(s->fd, (struct sockaddr *) &cli.addr, &len);
	if (fd == -1)
		return 0;

	struct client_ctx *cc = calloc(sizeof(*cc), 1);

	cc->fd = fd;
	
	return cc;
}

int socket_new(struct socket *s, char *path)
{
	memset(&s->addr, 0, sizeof(s->addr));

	s->addr.sun_family = AF_UNIX;
	strcpy(s->addr.sun_path, path);

	s->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s->fd == -1) return 1;

	if (bind(s->fd, (struct sockaddr *) &s->addr, sizeof(s->addr)) == -1)
		return 1;

	if(listen(s->fd, SERVER_BACKLOG) == -1)
		return 1;

	return 0;
}

int socket_initialize()
{
	if (socket_new(&srv_http, config->unix_sock_path))
		return 1;

	return 0;
}

struct client_ctx *socket_nextclient()
{
	struct client_ctx *cc = socket_listen(&srv_http);
	log(LOG_SOCK, "Got connection");
	return cc;
}

void socket_terminate()
{
	close(srv_http.fd);
	unlink(config->unix_sock_path);
}

size_t socket_read(struct client_ctx *cc, char *buf, size_t len)
{
	char *bufp = buf;
	char packet[PACKET_SIZE];
	size_t packetsize = 0;

	while ((size_t) (bufp - buf) < len && (packetsize = read(cc->fd, packet, PACKET_SIZE)) > 0){
		memcpy(bufp, packet, packetsize);
		bufp += packetsize;
	}

	return bufp - buf;
}

void socket_write(struct client_ctx *cc, char *buf, ssize_t len)
{
	size_t packetsize = 0;

	while (len > 0){
		packetsize = MIN(len, PACKET_SIZE);
		if (write(cc->fd, buf, packetsize) <= 0)
			break;
		buf += packetsize;
		len -= packetsize;
	}
}

size_t socket_gets(struct client_ctx *cc, char *buf, size_t len)
{
	return read(cc->fd, buf, len);
}
