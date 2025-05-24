#include "EasySSH.h"
#include <fcntl.h>

struct EasySSH::Auth {

	ssh_session session = nullptr;

	Auth(ssh_session session);

	int operator () (PasswdAuth &auth);

	int operator () (PubkeyAuth &auth);

	int auth(AuthVar &auth);
};

struct EasySSH::SftpSimpleCommand {
	EasySSH *that;
	std::string name_;
	SftpSimpleCommand(EasySSH *that, std::string name);
	int operator () (MKDIR &cmd);
	int operator () (RMDIR &cmd);
	int visit(SftpCmd &cmd);
};

struct EasySSH::Private {
	unsigned int flags = 0;
	ssh_session session = nullptr;
	ssh_channel channel = nullptr;
	ssh_scp scp = nullptr;
	sftp_session sftp = nullptr;
};

EasySSH::EasySSH()
	: m(new Private)
{
}

EasySSH::~EasySSH()
{
	close();
	delete m;
}

bool EasySSH::exec(ssh_session session, const char *command, std::function<bool (const char *, int)> writer)
{
	int rc;
	char buffer[256];
	int nbytes;

	// チャネルの作成
	m->channel = ssh_channel_new(session);
	if (m->channel == NULL) {
		fprintf(stderr, "Failed to create SSH channel\n");
		return false;
	}

	// チャネルを開く
	rc = ssh_channel_open_session(m->channel);
	if (rc != SSH_OK) {
		fprintf(stderr, "Failed to open SSH channel: %s\n", ssh_get_error(session));
		// ssh_channel_free(channel);
		// return rc;
		// goto free_channel;
		return false;
	}

	// コマンドの実行
	rc = ssh_channel_request_exec(m->channel, command);
	if (rc != SSH_OK) {
		fprintf(stderr, "Failed to execute command: %s\n", ssh_get_error(session));
		// ssh_channel_close(channel);
		// ssh_channel_free(channel);
		// return rc;
		// goto close_channel;
		return false;
	}

	// コマンド結果を読み取る
	while ((nbytes = ssh_channel_read(m->channel, buffer, sizeof(buffer), 0)) > 0) {
		writer(buffer, nbytes);
		// fwrite(buffer, 1, nbytes, stdout);
	}

	// チャネルのクローズと解放
// 	ssh_channel_send_eof(m->channel);
// close_channel:
// 	ssh_channel_close(m->channel);
// free_channel:
// 	ssh_channel_free(m->channel);

	return true;
}

bool EasySSH::open(char const *host, int port, AuthVar authdata)
{
	bool ret = false;
	int rc;

	// SSHセッションの初期化
	m->session = ssh_new();
	if (!m->session) {
		fprintf(stderr, "Failed to create SSH session.\n");
		return false;
	}
	// m->flags |= SESSION_ALLOCATED;

	// サーバのホスト情報の設定
	ssh_options_set(m->session, SSH_OPTIONS_HOST, host);
	ssh_options_set(m->session, SSH_OPTIONS_PORT, &port);

	// サーバへ接続
	rc = ssh_connect(m->session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to %s: %s\n", host, ssh_get_error(m->session));
		return false;
	}
	// m->flags |= SESSION_CONNECTED;

	rc = Auth{m->session}.auth(authdata);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(m->session));
		return false;
	}

	return true;
}

void EasySSH::close()
{
	if (m->channel) {
		ssh_channel_close(m->channel);
		ssh_channel_free(m->channel);
		m->channel = nullptr;
	}
	if (m->scp) {
		ssh_scp_close(m->scp);
		ssh_scp_free(m->scp);
		m->scp = nullptr;
	}
	if (m->sftp) {
		sftp_free(m->sftp);
		m->sftp = nullptr;
	}
	if (m->session) {
		ssh_disconnect(m->session);
		ssh_free(m->session);
		m->session = nullptr;
	}
	m->flags = 0;
}

bool EasySSH::mkdir(const std::string &name)
{
	SftpCmd cmd = MKDIR{};
	return SftpSimpleCommand{this, name}.visit(cmd);
}

bool EasySSH::rmdir(const std::string &name)
{
	SftpCmd cmd = RMDIR{};
	return SftpSimpleCommand{this, name}.visit(cmd);
}

bool EasySSH::exec(const char *cmd, std::function<bool (const char *, int)> writer)
{
	return exec(m->session, cmd, writer);
}

bool EasySSH::push_file_scp(const std::string &path, std::function<int (char *, int)> reader, size_t size) // scp is deprecated
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
	m->scp = ssh_scp_new(m->session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, dir.c_str());
	if (!m->scp) {
		fprintf(stderr, "Failed to create SCP session: %s\n", ssh_get_error(m->session));
		return false;
	}
	// m->flags |= SCP_ALLOCATED;

	// SCPセッションを開く
	rc = ssh_scp_init(m->scp);
	if (rc != SSH_OK) {
		fprintf(stderr, "Failed to initialize SCP: %s\n", ssh_get_error(m->session));
		return false;
	}

	// SCPでファイルをリモートサーバにコピー
	rc = ssh_scp_push_file(m->scp, name.c_str(), size, 0644);
	if (rc != SSH_OK) {
		fprintf(stderr, "SCP push failed: %s\n", ssh_get_error(m->session));
		return false;
	}

	while (1) {
		char tmp[1024];
		int nbytes = reader(tmp, sizeof(tmp));
		if (nbytes < 1) break;
		ssh_scp_write(m->scp, tmp, nbytes);
	}

	fprintf(stderr, "File transferred successfully.\n");
	return true;
}

bool EasySSH::push_file_sftp(const std::string &path, std::function<int (char *, int)> reader)
{
	sftp_file file;
	int rc;

	if (!m->sftp) {
		// SFTPセッションを初期化
		m->sftp = sftp_new(m->session);
		if (!m->sftp) {
			fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(m->session));
			return false;
		}
		// m->flags |= SFTP_ALLOCATED;

		// SFTPセッションを開く
		rc = sftp_init(m->sftp);
		if (rc != SSH_OK) {
			fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(m->session));
			// sftp_free(m->sftp);
			return false;
		}
	}

#if 0
	std::string filepath = path;
	sftp_attributes st = sftp_stat(m->session, path.c_str());
	if (st) {
		sftp_attributes_free(st);
	}
#endif

	// ファイルをリモートサーバにコピー
	file = sftp_open(m->sftp, path.c_str(), O_WRONLY | O_CREAT, 0644);
	if (!file) {
		fprintf(stderr, "Failed to open file: %s\n", ssh_get_error(m->session));
		// sftp_free(m->sftp);
		return false;
	}

	while (1) {
		char tmp[1024];
		int nbytes = reader(tmp, sizeof(tmp));
		if (nbytes < 1) break;
		sftp_write(file, tmp, nbytes);
	}

	sftp_close(file);

	return true;
}

bool EasySSH::pull_file_scp(std::function<bool (const char *, int)> writer) // scp is deprecated
{
	std::string remote_file = "/tmp/example.txt";

	char buffer[1024];
	int nbytes;
	int total = 0;

	if (!m->sftp) {
		// SCPセッションの初期化
		m->scp = ssh_scp_new(m->session, SSH_SCP_READ, remote_file.c_str());
		if (m->scp == NULL) {
			fprintf(stderr, "Error initializing SCP session: %s\n", ssh_get_error(m->session));
			return false;
		}
		// m->flags |= SCP_ALLOCATED;

		if (ssh_scp_init(m->scp) != SSH_OK) {
			fprintf(stderr, "Error initializing SCP: %s\n", ssh_get_error(m->session));
			return false;
		}
	}

	int rc;
	rc = ssh_scp_pull_request(m->scp);
	if (rc != SSH_SCP_REQUEST_NEWFILE) {
		fprintf(stderr, "Error requesting file: %s\n", ssh_get_error(m->session));
		return false;
	}
	auto size = ssh_scp_request_get_size(m->scp);
	// auto *filename = ssh_scp_request_get_filename(scp_);
	// auto mode = ssh_scp_request_get_permissions(scp_);

	// リモートファイルの受け入れ
	if (ssh_scp_accept_request(m->scp) != SSH_OK) {
		fprintf(stderr, "Error accepting SCP request: %s\n", ssh_get_error(m->session));
		return false;
	}

	//
	total = 0;
	while (total < size) {
		nbytes = ssh_scp_read(m->scp, buffer, size - total);
		if (nbytes < 0) {
			fprintf(stderr, "Error receiving file: %s\n", ssh_get_error(m->session)); // エラーメッセージを表示
			break;
		}

		// printf("%d\n", nbytes);
		if (writer(buffer, nbytes) < 1) break;
		total += nbytes;
	}

	return true;
}

bool EasySSH::pull_file_sftp(const std::string &remote_path, std::function<int (char *, int)> writer)
{
	sftp_session sftp;
	sftp_file file;
	int rc;

	// SFTPセッションを初期化
	sftp = sftp_new(m->session);
	if (!sftp) {
		fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(m->session));
		return false;
	}
	// m->flags |= SFTP_ALLOCATED;

	// SFTPセッションを開く
	rc = sftp_init(sftp);
	if (rc != SSH_OK) {
		fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(m->session));
		return false;
	}

	// ファイルをリモートサーバからコピー
	file = sftp_open(sftp, remote_path.c_str(), O_RDONLY, 0);
	if (!file) {
		fprintf(stderr, "Failed to open file: %s\n", ssh_get_error(m->session));
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

bool EasySSH::push_file(const std::string &path, std::function<int (char *, int)> reader)
{
	return push_file_sftp(path, reader);
}

bool EasySSH::pull_file(const std::string &remote_path, std::function<int (const char *, int)> writer)
{
	return pull_file_sftp(remote_path, writer);
}

struct stat EasySSH::stat(const std::string &path)
{
	struct stat st;
	sftp_attributes attr;
	m->sftp = sftp_new(m->session);
	if (!m->sftp) {
		fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(m->session));
		return st;
	}
	// m->flags |= SFTP_ALLOCATED;

	if (sftp_init(m->sftp) != SSH_OK) {
		fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(m->session));
		return st;
	}

	attr = sftp_stat(m->sftp, path.c_str());
	if (!attr) {
		fprintf(stderr, "Failed to stat file: %s\n", ssh_get_error(m->session));
		sftp_free(m->sftp);
		return st;
	}
	st.st_size = attr->size;
	st.st_mode = attr->permissions;
	sftp_attributes_free(attr);

	return st;
}

EasySSH::Auth::Auth(ssh_session session)
	: session(session)
{
}

int EasySSH::Auth::operator ()(PasswdAuth &auth)
{
	ssh_options_set(session, SSH_OPTIONS_USER, auth.uid.c_str());
	return ssh_userauth_password(session, NULL, auth.pwd.c_str());
	if (auth.pwd.empty()) {
		return ssh_userauth_none(session, NULL);
	} else {
		return ssh_userauth_password(session, NULL, auth.pwd.c_str());
	}
}

int EasySSH::Auth::operator ()(PubkeyAuth &auth)
{
	return ssh_userauth_publickey_auto(session, NULL, NULL);
}

int EasySSH::Auth::auth(AuthVar &auth)
{
	return std::visit(*this, auth);
}

EasySSH::SftpSimpleCommand::SftpSimpleCommand(EasySSH *that, std::string name)
	: that(that)
	, name_(name)
{
}

int EasySSH::SftpSimpleCommand::operator ()(MKDIR &cmd)
{
	return sftp_mkdir(that->m->sftp, name_.c_str(), 0755);
}

int EasySSH::SftpSimpleCommand::operator ()(RMDIR &cmd)
{
	return sftp_rmdir(that->m->sftp, name_.c_str());
}

int EasySSH::SftpSimpleCommand::visit(SftpCmd &cmd)
{
	that->m->sftp = sftp_new(that->m->session);
	if (!that->m->sftp) {
		fprintf(stderr, "Failed to create SFTP session: %s\n", ssh_get_error(that->m->session));
		return false;
	}
	// that->m->flags |= SFTP_ALLOCATED;

	if (sftp_init(that->m->sftp) != SSH_OK) {
		fprintf(stderr, "Failed to initialize SFTP: %s\n", ssh_get_error(that->m->session));
		sftp_free(that->m->sftp);
		return false;
	}
	int rc = std::visit(*this, cmd);
	return rc == SSH_OK;
}
