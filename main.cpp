#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <variant>
#include <string>
#include <fcntl.h>

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
				return ssh_userauth_none(session, NULL);
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

	bool push_file_scp() // scp is deprecated
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

	bool push_file_sftp()
	{
		std::string filename = "/tmp/example.txt";
		std::string data = "Hello, world";

		sftp_session sftp;
		sftp_file file;
		int rc;

		// SFTPセッションを初期化
		sftp = sftp_new(session_);
		if (!sftp) {
			fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(session_));
			return false;
		}

		// SFTPセッションを開く
		rc = sftp_init(sftp);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}

		// ファイルをリモートサーバにコピー
		file = sftp_open(sftp, filename.c_str(), O_WRONLY | O_CREAT, 0644);
		if (!file) {
			fprintf(stderr, "Failed to open file: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}


		ssize_t nbytes;
		nbytes = sftp_write(file, data.c_str(), data.size());

		sftp_close(file);
		sftp_free(sftp);

		fprintf(stderr, "File transferred successfully.\n");
		return true;
	}

	bool pull_file_scp() // scp is deprecated
	{
		std::string remote_file = "/tmp/example.txt";

		char buffer[1024];
		int nbytes;
		int total = 0;

		// SCPセッションの初期化
		scp_ = ssh_scp_new(session_, SSH_SCP_READ, remote_file.c_str());
		if (scp_ == NULL) {
			fprintf(stderr, "Error initializing SCP session: %s\n", ssh_get_error(session_));
			return false;
		}
		flags_ |= SCP_ALLOCATED;

		if (ssh_scp_init(scp_) != SSH_OK) {
			fprintf(stderr, "Error initializing SCP: %s\n", ssh_get_error(session_));
			ssh_scp_free(scp_);
			return false;
		}
		flags_ |= SCP_OPENED;

		int rc;
		rc = ssh_scp_pull_request(scp_);
		if (rc != SSH_SCP_REQUEST_NEWFILE) {
			fprintf(stderr, "Error requesting file: %s\n", ssh_get_error(session_));
			return false;
		}
		auto size = ssh_scp_request_get_size(scp_);
		auto *filename = ssh_scp_request_get_filename(scp_);
		auto mode = ssh_scp_request_get_permissions(scp_);

		// リモートファイルの受け入れ
		if (ssh_scp_accept_request(scp_) != SSH_OK) {
			fprintf(stderr, "Error accepting SCP request: %s\n", ssh_get_error(session_));
			return false;
		}

		//
		total = 0;
		while (total < size) {
			nbytes = ssh_scp_read(scp_, buffer, size - total);
			if (nbytes < 0) {
				fprintf(stderr, "Error receiving file: %s\n", ssh_get_error(session_)); // エラーメッセージを表示
				break;
			}

			// printf("%d\n", nbytes);
			fwrite(buffer, 1, nbytes, stdout);
			total += nbytes;
		}

		return true;
	}

	bool pull_file_sftp()
	{
		std::string remote_file = "/tmp/example.txt";

		sftp_session sftp;
		sftp_file file;
		int rc;

		// SFTPセッションを初期化
		sftp = sftp_new(session_);
		if (!sftp) {
			fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(session_));
			return false;
		}

		// SFTPセッションを開く
		rc = sftp_init(sftp);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}

		// ファイルをリモートサーバからコピー
		file = sftp_open(sftp, remote_file.c_str(), O_RDONLY, 0);
		if (!file) {
			fprintf(stderr, "Failed to open file: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}

		// ファイルの内容を読み取る
		char buffer[1024];
		int nbytes;
		while ((nbytes = sftp_read(file, buffer, sizeof(buffer))) > 0) {
			fwrite(buffer, 1, nbytes, stdout);
		}

		sftp_close(file);
		sftp_free(sftp);

		return true;
	}

	bool push_file()
	{
		return push_file_sftp();
	}

	bool pull_file()
	{
		return pull_file_sftp();
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
	// ssh.exec("uname -a");
	// ssh.push_file_sftp();
	// ssh.pull_file_scp();
	ssh.pull_file();
	ssh.close();
	return 0;
}

