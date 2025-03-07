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

class SSH {
public:
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
			if (auth.pwd.empty()) {
i				return ssh_userauth_none(session, NULL);
			} else {
				return ssh_userauth_password(session, NULL, auth.pwd.c_str());
			}
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
private:
	enum {
		SESSION_ALLOCATED = 0x0001,
		SESSION_OPENED = 0x0002,
		SCP_ALLOCATED = 0x0004,
		SCP_OPENED = 0x0008,
		CHANNEL_ALLOCATED = 0x0010,
		CHANNEL_OPENED = 0x0020,
	};
	unsigned int flags_ = 0;
	ssh_session session_ = nullptr;
	ssh_channel channel_ = nullptr;
	ssh_scp scp_ = nullptr;

	int exec(ssh_session session, const char *command)
	{
		int rc;
		char buffer[256];
		int nbytes;

		// チャネルの作成
		channel_ = ssh_channel_new(session);
		if (channel_ == NULL) {
			fprintf(stderr, "Failed to create SSH channel\n");
			return SSH_ERROR;
		}

		// チャネルを開く
		rc = ssh_channel_open_session(channel_);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to open SSH channel: %s\n", ssh_get_error(session));
			// ssh_channel_free(channel);
			// return rc;
			goto free_channel;
		}

		// コマンドの実行
		rc = ssh_channel_request_exec(channel_, command);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to execute command: %s\n", ssh_get_error(session));
			// ssh_channel_close(channel);
			// ssh_channel_free(channel);
			// return rc;
			goto close_channel;
		}

		// コマンド結果を読み取る
		while ((nbytes = ssh_channel_read(channel_, buffer, sizeof(buffer), 0)) > 0) {
			fwrite(buffer, 1, nbytes, stdout);
		}

		// チャネルのクローズと解放
		ssh_channel_send_eof(channel_);
close_channel:
		ssh_channel_close(channel_);
free_channel:
		ssh_channel_free(channel_);

		return SSH_OK;
	}
public:
	bool open(AuthVar authdata)
	{
		bool ret = false;
		int rc;

		// SSHセッションの初期化
		session_ = ssh_new();
		if (!session_) {
			fprintf(stderr, "Failed to create SSH session.\n");
			return false;
		}
		flags_ |= SESSION_ALLOCATED;

		// サーバのホスト情報の設定
		ssh_options_set(session_, SSH_OPTIONS_HOST, HOST);

		// サーバへ接続
		rc = ssh_connect(session_);
		if (rc != SSH_OK) {
			fprintf(stderr, "Error connecting to %s: %s\n", HOST, ssh_get_error(session_));
			return false;
		}
		flags_ |= SESSION_OPENED;

		rc = Auth{session_}.auth(authdata);
		if (rc != SSH_AUTH_SUCCESS) {
			fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session_));
			return false;
		}

		return true;
	}

	bool exec(char const *cmd)
	{
		return exec(session_, cmd);
	}

	bool push_file()
	{
		std::string dir = "/tmp";
		std::string filename = "example.txt";
		std::string data = "Hello, world";

		int rc;

		// SCPセッションを初期化
		scp_ = ssh_scp_new(session_, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, dir.c_str());
		if (!scp_) {
			fprintf(stderr, "Failed to create SCP session: %s\n", ssh_get_error(session_));
			return false;
		}
		flags_ |= SCP_ALLOCATED;

		// SCPセッションを開く
		rc = ssh_scp_init(scp_);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to initialize SCP: %s\n", ssh_get_error(session_));
			return false;
		}
		flags_ |= SCP_OPENED;

		// SCPでファイルをリモートサーバにコピー
		rc = ssh_scp_push_file(scp_, filename.c_str(), data.size(), 0644);
		if (rc != SSH_OK) {
			fprintf(stderr, "SCP push failed: %s\n", ssh_get_error(session_));
			return false;
		}

		ssh_scp_write(scp_, data.c_str(), data.size());

		fprintf(stderr, "File transferred successfully.\n");
		return true;
	}

	void close()
	{
		if (flags_ & CHANNEL_OPENED) {
			ssh_channel_close(channel_);
		}
		if (flags_ & CHANNEL_ALLOCATED) {
			ssh_channel_free(channel_);
		}
		if (flags_ & SCP_OPENED) {
			ssh_scp_close(scp_);
		}
		if (flags_ & SCP_ALLOCATED) {
			ssh_scp_free(scp_);
		}
		if (flags_ & SESSION_OPENED) {
			ssh_disconnect(session_);
		}
		if (flags_ & SESSION_ALLOCATED) {
			ssh_free(session_);
		}
		flags_ = 0;
	}
};

int main()
{
#if 0
		SSH::AuthVar authdata = SSH::PasswdAuth{"user123", "pass123"};
#else
		SSH::AuthVar authdata = SSH::PubkeyAuth{};
#endif

	SSH ssh;
	ssh.open(authdata);
	ssh.exec("uname -a");
	ssh.push_file();
	ssh.close();
	return 0;
}

