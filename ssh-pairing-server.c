// SPDX-License-Identifier: GPL-2.0-or-later

#define _GNU_SOURCE

#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#define MAX_KEY_COUNT 10

int main(int argc, char *argv[])
{
	if (argc != 1) {
		fprintf(stderr, "Usage: ssh-pairing-server\n\n"
		                "SSH server which prints received public keys to stdout.\n"
				"It uses libssh's default config and accepts only a single connection.\n");
		exit(1);
	}

	ssh_bind bind = ssh_bind_new();

	// If a file doesn't exist it's ignored. If no host keys are available,
	// ssh_bind_listen will fail immediately with a helpful error.
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_ecdsa_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_ed25519_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_rsa_key");

	if (ssh_bind_listen(bind) < 0) {
		fprintf(stderr, "Failed to listen: %s\n", ssh_get_error(bind));
		return 1;
	}

	ssh_session session = ssh_new();

	if (ssh_bind_accept(bind, session) != SSH_OK) {
		fprintf(stderr, "Failed to accept: %s\n", ssh_get_error(bind));
		return 1;
	}

	// Client identifier to be used in the authorized_keys comment section (user@host)
	char clientname[NI_MAXHOST] = "ssh-pairing";

	// Get the client IP if possible, avoid a potentially slow reverse lookup.
	{
		struct sockaddr_storage sa;
		socklen_t sa_len = sizeof(sa);
		if (getpeername(ssh_get_fd(session), (struct sockaddr*) &sa, &sa_len) == 0)
			getnameinfo((struct sockaddr*) &sa, sa_len,
			            clientname, sizeof(clientname), NULL, 0, NI_NUMERICHOST);
	}

	if (ssh_handle_key_exchange(session)) {
		fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
		return 1;
	}

	// Handle messages until all pubkey auth requests are done and either
	// the client moves on to keyboard-interactive or disconnects due to no
	// further methods. The use of keyboard-interactive means that unfortunately
	// the callback-based pubkey handling is not possible:
	// https://gitlab.com/libssh/libssh-mirror/-/issues/146

	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE);

	int keycount = 0;
	bool confirmation_sent = false;

	ssh_message message;
	while ((message = ssh_message_get(session))) {
		int msg_type = ssh_message_type(message),
		    msg_subtype = ssh_message_subtype(message);

		if (msg_type == SSH_REQUEST_AUTH && msg_subtype == SSH_AUTH_METHOD_PUBLICKEY && keycount < MAX_KEY_COUNT) {
			ssh_key pubkey = ssh_message_auth_pubkey(message);
			char *key_fp = NULL;
			if (ssh_pki_export_pubkey_base64(pubkey, &key_fp) == 0) {
				const char *key_type = ssh_key_type_to_char(ssh_key_type(pubkey));
				printf("%s %s %s@%s\n",
				       key_type, key_fp, ssh_message_auth_user(message), clientname);
				keycount += 1;
			}
			SSH_STRING_FREE_CHAR(key_fp);
		} else if (msg_type == SSH_REQUEST_AUTH && msg_subtype == SSH_AUTH_METHOD_INTERACTIVE) {
			// A reply to the confirmation message means the message arrived.
			if (ssh_message_auth_kbdint_is_response(message)) {
				confirmation_sent = true;
				ssh_message_free(message);
				break;
			}

			// Send a confirmation message. No prompts means it responds immediately.
			char *msg = NULL;
			if (asprintf(&msg, "ssh-pairing: Received %d public keys", keycount) > 0) {
				ssh_message_auth_interactive_request(message, msg, "", 0, NULL, 0);
				free(msg);
			}
			ssh_message_free(message);
			continue;
		}

		if (keycount < MAX_KEY_COUNT)
			ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE);
		else
			ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_INTERACTIVE);

		ssh_message_reply_default(message);
		ssh_message_free(message);
	}

	ssh_disconnect(session);
	ssh_free(session);
	ssh_bind_free(bind);
	ssh_finalize();

	if (!confirmation_sent) {
		fprintf(stderr, "Session did not complete until keyboard-interactive.\n");
		return 1;
	}

	return 0;
}
