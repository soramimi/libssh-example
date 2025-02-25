#include <libssh/libssh.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <variant>
#include <string>

#define HOST "127.0.0.1"
#define LOCAL_FILE "example.txt"
#define REMOTE_PATH "/tmp/example.txt"

struct PasswdAuth {
	std::string uid;
	std::string pwd;
};

struct PubkeyAuth {
};

using AuthVar = std::variant<PasswdAuth, PubkeyAuth>;

struct Auth {

	ssh_session session = nullptr;

	Auth(ssh_session session)
		: session(session)
	{
	}

	int operator () (PasswdAuth &auth)
	{
		ssh_options_set(session, SSH_OPTIONS_USER, auth.uid.c_str());
		return ssh_userauth_password(session, NULL, auth.pwd.c_str());
	}

	int operator () (PubkeyAuth &auth)
	{
		return ssh_userauth_publickey_auto(session, NULL, NULL);
	}

	int auth(AuthVar &auth)
	{
		return std::visit(*this, auth);
	}
};

bool scp_example()
{
#if 0
	AuthVar authdata = PasswdAuth{"user123", "pass123"};
#else
	AuthVar authdata = PubkeyAuth{};
#endif

	std::string dir = "/tmp";
	std::string filename = "example.txt";
	std::string data = "Hello, world";

	bool ret = false;
	ssh_session session = nullptr;
	ssh_scp scp = nullptr;
	int rc;

	// SSHセッションの初期化
	session = ssh_new();
	if (!session) {
		fprintf(stderr, "Failed to create SSH session.\n");
		return false;
	}

	// サーバのホスト情報の設定
	ssh_options_set(session, SSH_OPTIONS_HOST, HOST);

	// サーバへ接続
	rc = ssh_connect(session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to %s: %s\n", HOST, ssh_get_error(session));
		goto free_session;
	}

	rc = Auth{session}.auth(authdata);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
		goto disconnect_session;
	}

	// SCPセッションを初期化
	scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, dir.c_str());
	if (!scp) {
		fprintf(stderr, "Failed to create SCP session: %s\n", ssh_get_error(session));
		goto disconnect_session;
	}

	// SCPセッションを開く
	rc = ssh_scp_init(scp);
	if (rc != SSH_OK) {
		fprintf(stderr, "Failed to initialize SCP: %s\n", ssh_get_error(session));
		goto free_scp;
	}

	// SCPでファイルをリモートサーバにコピー
	rc = ssh_scp_push_file(scp, filename.c_str(), data.size(), 0644);
	if (rc != SSH_OK) {
		fprintf(stderr, "SCP push failed: %s\n", ssh_get_error(session));
		goto free_scp;
	}

	ssh_scp_write(scp, data.c_str(), data.size());

	ret = true;

close_scp:
	ssh_scp_close(scp);
free_scp:
	ssh_scp_free(scp);
disconnect_session:
	ssh_disconnect(session);
free_session:
	ssh_free(session);

	if (ret) {
		fprintf(stderr, "File transferred successfully.\n");
	}

	return ret;
}

int main()
{
	scp_example();
	return 0;
}
