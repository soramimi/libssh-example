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
#include <functional>
#include <variant>

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
		SESSION_CONNECTED = 0x0002,
		CHANNEL_ALLOCATED = 0x0004,
		CHANNEL_OPENED = 0x0008,
		SCP_ALLOCATED = 0x0010,
		SCP_OPENED = 0x0020,
		SFTP_ALLOCATED = 0x0040,
	};
	unsigned int flags_ = 0;
	ssh_session session_ = nullptr;
	ssh_channel channel_ = nullptr;
	ssh_scp scp_ = nullptr;
	sftp_session sftp_ = nullptr;

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
		flags_ |= SESSION_CONNECTED;

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

	bool push_file_scp(std::string const &path, std::function<int (char *ptr, int len)> reader, size_t size) // scp is deprecated
	{
		std::string dir;
		std::string name = path;
		{
			auto i = name.rfind('/');
			if (i != std::string::npos) {
				dir = name.substr(0, i);
				name = name.substr(i + 1);
			}
		}

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

		// SCPでファイルをリモートサーバにコピー
		rc = ssh_scp_push_file(scp_, name.c_str(), size, 0644);
		if (rc != SSH_OK) {
			fprintf(stderr, "SCP push failed: %s\n", ssh_get_error(session_));
			return false;
		}

		while (1) {
			char tmp[1024];
			int nbytes = reader(tmp, sizeof(tmp));
			if (nbytes < 1) break;
			ssh_scp_write(scp_, tmp, nbytes);
		}

		fprintf(stderr, "File transferred successfully.\n");
		return true;
	}

	bool push_file_sftp(std::string const &path, std::function<int (char *ptr, int len)> reader)
	{
		sftp_session sftp;
		sftp_file file;
		int rc;

		// SFTPセッションを初期化
		sftp = sftp_new(session_);
		if (!sftp) {
			fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(session_));
			return false;
		}
		flags_ |= SCP_ALLOCATED;

		// SFTPセッションを開く
		rc = sftp_init(sftp);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}

		// ファイルをリモートサーバにコピー
		file = sftp_open(sftp, path.c_str(), O_WRONLY | O_CREAT, 0644);
		if (!file) {
			fprintf(stderr, "Failed to open file: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}

		while (1) {
			char tmp[1024];
			int nbytes = reader(tmp, sizeof(tmp));
			if (nbytes < 1) break;
			sftp_write(file, tmp, nbytes);
		}

		sftp_close(file);
		sftp_free(sftp);

		fprintf(stderr, "File transferred successfully.\n");
		return true;
	}

	bool pull_file_scp(std::function<bool (char const *ptr, int len)> writer) // scp is deprecated
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
			return false;
		}

		int rc;
		rc = ssh_scp_pull_request(scp_);
		if (rc != SSH_SCP_REQUEST_NEWFILE) {
			fprintf(stderr, "Error requesting file: %s\n", ssh_get_error(session_));
			return false;
		}
		auto size = ssh_scp_request_get_size(scp_);
		// auto *filename = ssh_scp_request_get_filename(scp_);
		// auto mode = ssh_scp_request_get_permissions(scp_);

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
			if (writer(buffer, nbytes) < 1) break;
			total += nbytes;
		}

		return true;
	}

	bool pull_file_sftp(std::string const &remote_path, std::function<int (char *ptr, int len)> writer)
	{
		sftp_session sftp;
		sftp_file file;
		int rc;

		// SFTPセッションを初期化
		sftp = sftp_new(session_);
		if (!sftp) {
			fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(session_));
			return false;
		}
		flags_ |= SFTP_ALLOCATED;

		// SFTPセッションを開く
		rc = sftp_init(sftp);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(session_));
			return false;
		}

		// ファイルをリモートサーバからコピー
		file = sftp_open(sftp, remote_path.c_str(), O_RDONLY, 0);
		if (!file) {
			fprintf(stderr, "Failed to open file: %s\n", ssh_get_error(session_));
			sftp_free(sftp);
			return false;
		}

		// ファイルの内容を読み取る
		char buffer[1024];
		int nbytes;
		while ((nbytes = sftp_read(file, buffer, sizeof(buffer))) > 0) {
			if (writer(buffer, nbytes) < 1) break;
		}

		sftp_close(file);

		return true;
	}

	bool push_file(std::string const &path, std::function<int (char *ptr, int len)> reader)
	{
		return push_file_sftp(path, reader);
	}

	bool pull_file(std::string const &remote_path, std::function<int (char const *ptr, int len)> writer)
	{
		return pull_file_sftp(remote_path, writer);
	}

	struct ::stat stat(std::string const &path)
	{
		struct stat st;
		sftp_attributes attr;
		sftp_ = sftp_new(session_);
		if (!sftp_) {
			fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(session_));
			return st;
		}
		flags_ |= SFTP_ALLOCATED;

		if (sftp_init(sftp_) != SSH_OK) {
			fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(session_));
			return st;
		}

		attr = sftp_stat(sftp_, path.c_str());
		if (!attr) {
			fprintf(stderr, "Failed to stat file: %s\n", ssh_get_error(session_));
			sftp_free(sftp_);
			return st;
		}
		st.st_size = attr->size;
		st.st_mode = attr->permissions;
		sftp_attributes_free(attr);

		return st;
	}
private:
	struct MKDIR {
	};
	struct RMDIR {
	};
	typedef std::variant<MKDIR, RMDIR> SftpCmd;
	struct SftpSimpleCommand {
		SSH *that;
		std::string name_;
		SftpSimpleCommand(SSH *that, std::string name)
			: that(that)
			, name_(name)
		{
		}
		int operator () (MKDIR &cmd)
		{
			return sftp_mkdir(that->sftp_, name_.c_str(), 0755);
		}
		int operator () (RMDIR &cmd)
		{
			return sftp_rmdir(that->sftp_, name_.c_str());
		}
		int visit(SftpCmd &cmd)
		{
			that->sftp_ = sftp_new(that->session_);
			if (!that->sftp_) {
				fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(that->session_));
				return false;
			}
			that->flags_ |= SFTP_ALLOCATED;

			if (sftp_init(that->sftp_) != SSH_OK) {
				fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(that->session_));
				sftp_free(that->sftp_);
				return false;
			}
			int rc = std::visit(*this, cmd);
			return rc == SSH_OK;
		}
	};
public:
	bool mkdir(std::string const &name)
	{
		SftpCmd cmd = MKDIR{};
		return SftpSimpleCommand{this, name}.visit(cmd);
	}

	bool rmdir(std::string const &name)
	{
		SftpCmd cmd = RMDIR{};
		return SftpSimpleCommand{this, name}.visit(cmd);
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
		if (flags_ & SFTP_ALLOCATED) {
			sftp_free(sftp_);
		}
		if (flags_ & SESSION_CONNECTED) {
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

	char const *data = "Hello, world";
	int offset = 0;
	int length = strlen(data);

	auto Reader = [&data, &offset, length](char *ptr, int len) {
		if (offset < length) {
			int n = std::min(len, length - offset);
			memcpy(ptr, data + offset, n);
			offset += n;
			return n;
		}
		return 0;
	};

	auto Writer = [](char const *ptr, int len) {
		return fwrite(ptr, 1, len, stdout);
	};

	SSH ssh;
	ssh.open(authdata);
	ssh.exec("uname -a");
	// ssh.mkdir("/tmp/hogehoge");
	// ssh.rmdir("/tmp/hogehoge");
	// ssh.push_file("/tmp/example.txt", Reader);
	// ssh.pull_file("/tmp/example.txt", Writer);
	ssh.close();
	return 0;
}

