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

/*
 * processing argv and providing a minimal usage / --help message describing
 * what this program does would be helpful for any production level tool.
 */
int main(int argc, char *argv[])
{
	ssh_bind bind = ssh_bind_new();

	// If a file doesn't exist it's ignored. If no host keys are available,
	// ssh_bind_listen will fail immediately with a helpful error.
	/*
	 * this mimics the current default host key settings for sshd.
	 *
	 * if these should ever change then we get an inconsistency. would it
	 * be possible to query these paths from libssh?
	 *
	 * furthermore, what if in sshd_config different settings are found? I
	 * understand this tool is focused on setting up new installs, but
	 * even custom images could have custom sshd settings, in which case
	 * this might produce bad results.
	 */
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_ecdsa_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_ed25519_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_rsa_key");

	/*
	 * the default settings from libssh result in sshd listening on IPv4
	 * only on the wildcard address 0.0.0.0.
	 *
	 * custom settings in sshd_config are for some reason not honored
	 * (tested on Tumbleweed with sshd_config in
	 * /usr/etc/ssh/sshd_config).
	 *
	 * also why does it listen only on IPv4, not on IPv6?
	 *
	 * even in new image installations there might be different network
	 * security domains, so listening on all interfaces might be
	 * undesirable.
	 */
	if (ssh_bind_listen(bind) < 0) {
		fprintf(stderr, "Failed to listen: %s\n", ssh_get_error(bind));
		return 1;
	}

	ssh_session session = ssh_new();

	if (ssh_bind_accept(bind, session) != SSH_OK) {
		fprintf(stderr, "Failed to accept: %s\n", ssh_get_error(bind));
		return 1;
	}

	// Client identifier
	char clientname[INET6_ADDRSTRLEN];
	/*
	 * what is the purpose of this "ssh-pairing" default value of
	 * `clientname`. I find this spot confusing:
	 *
	 * - it's not really a `clientname`, it's a client's IP address.
	 * - INET6_ADDRSTRLEN is the maximum string length for an IPv6
	 *   numerical address, but you are copying an arbitrary string label
	 *   into it. As luck has it, it fits in there, but semantically it
	 *   doesn't really make any sense.
	 */
	strlcpy(clientname, "ssh-pairing", sizeof(clientname));

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

	/*
	 * I don't really get why the INTERACTIVE auth method is offered in
	 * the first place. It looks like the only purpose is to send the
	 * "Received %d public keys" message to the connecting client. This
	 * should be documented better.
	 */
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE);

	char *authorized_keys = strdup("");
	int keycount = 0;

	ssh_message message;
	while ((message = ssh_message_get(session))) {
		/* I would move the processing done in the while loop into a
		 * separate function to get more digestible code portions */
		int msg_type = ssh_message_type(message),
		    msg_subtype = ssh_message_subtype(message);

		if (msg_type == SSH_REQUEST_AUTH && msg_subtype == SSH_AUTH_METHOD_PUBLICKEY && keycount < MAX_KEY_COUNT) {
			ssh_key pubkey = ssh_message_auth_pubkey(message);
			char *key_fp = NULL;
			if(ssh_pki_export_pubkey_base64(pubkey, &key_fp) == 0) {
				const char *key_type = ssh_key_type_to_char(ssh_key_type(pubkey));
				char *new_authorized_keys;
				/*
				 * displaying IP addresses  could give a false
				 * sense of security. On this level the IP
				 * address / the message is not verified in
				 * any way, except if there would be a client
				 * verification, but the client is not
				 * authenticated, it just presents its random
				 * public keys to the server.
				 *
				 * a network level attacker could spoof IP
				 * addresses and this way the output might
				 * look authentic, although it really isn't.
				 */
				/*
				 * instead of concatenating all keys into one
				 * big `authorized_keys` string I would simply
				 * format and print each key as it is
				 * encountered.
				 **/
				if (asprintf(&new_authorized_keys, "%s%s %s %s@%s\n",
				             authorized_keys, key_type, key_fp, ssh_message_auth_user(message), clientname) > 0) {
					free(authorized_keys);
					authorized_keys = new_authorized_keys;
					keycount += 1;
				}
				free(key_fp);
			}
		} else if (msg_type == SSH_REQUEST_AUTH && msg_subtype == SSH_AUTH_METHOD_INTERACTIVE) {
			char *msg = NULL;
			/*
			 * I nearly overlooked that this message goes out to
			 * the connecting client, not to stdout.
			 *
			 * Providing any information to a yet unauthenticated
			 * client can quickly become problematic. It looks
			 * like we are only reporting back what the client
			 * already knows: the amount of public keys it sent to
			 * us, the username it used and the IP address it
			 * uses.
			 *
			 * At least the latter (the IP address) could be a
			 * small information leak in some setups where some
			 * form of proxy / forwarding / NAT whatever is used.
			 * In this case the IP address would leak some network
			 * topology detail to unauthenticated clients.
			 *
			 * I'm not sure if there is much value in sending this
			 * out to the unauthenticated client. The user that
			 * rightfully uses this tool has two interaction
			 * points: The server side and the client side. It
			 * could be more clean and more secure to restrict
			 * any kind of informational output messages to the
			 * server side.
			 *
			 * Then you could also drop this INTERACTIVE auth path
			 * and make the code simpler.
			 */
			if (asprintf(&msg, "Received %d public keys from %s@%s", keycount, ssh_message_auth_user(message), clientname) > 0) {
				ssh_message_auth_interactive_request(message, msg, "", 0, NULL, 0);
				free(msg);
			}
			ssh_message_free(message);
			break;
		}

		if (keycount < MAX_KEY_COUNT)
			ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_INTERACTIVE);
		else
			ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_INTERACTIVE);

		ssh_message_reply_default(message);
        ssh_message_free(message);
    }

	printf("%s", authorized_keys);
	free(authorized_keys);
	authorized_keys = NULL;

	ssh_disconnect(session);
	ssh_free(session);
	ssh_bind_free(bind);
	ssh_finalize();
}
