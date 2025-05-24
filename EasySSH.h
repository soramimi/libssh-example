#ifndef EASYSSH_H
#define EASYSSH_H

#include <functional>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <string.h>
#include <string>
#include <variant>

class EasySSH {
public:
	struct PasswdAuth {
		std::string uid;
		std::string pwd;
	};

	struct PubkeyAuth {
	};

	using AuthVar = std::variant<PasswdAuth, PubkeyAuth>;

	struct Auth;
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

	struct Private;
	Private *m;

	int exec(ssh_session session, const char *command);
public:
	EasySSH();
	~EasySSH();
	EasySSH(EasySSH const &) = delete;
	EasySSH &operator=(EasySSH const &) = delete;
	EasySSH(EasySSH &&) = delete;
	EasySSH &operator=(EasySSH &&) = delete;

	bool open(const char *host, AuthVar authdata);
	bool exec(char const *cmd);
	bool push_file_scp(std::string const &path, std::function<int (char *ptr, int len)> reader, size_t size);
	bool push_file_sftp(std::string const &path, std::function<int (char *ptr, int len)> reader);
	bool pull_file_scp(std::function<bool (char const *ptr, int len)> writer);
	bool pull_file_sftp(std::string const &remote_path, std::function<int (char *ptr, int len)> writer);
	bool push_file(std::string const &path, std::function<int (char *ptr, int len)> reader);
	bool pull_file(std::string const &remote_path, std::function<int (char const *ptr, int len)> writer);
	struct stat stat(std::string const &path);
private:
	struct MKDIR {
	};
	struct RMDIR {
	};
	typedef std::variant<MKDIR, RMDIR> SftpCmd;
	struct SftpSimpleCommand;
public:
	bool mkdir(std::string const &name);

	bool rmdir(std::string const &name);

	void close();
};


#endif // EASYSSH_H
