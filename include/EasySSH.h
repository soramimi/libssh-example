#ifndef EASYSSH_H
#define EASYSSH_H

#include <functional>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <string.h>
#include <string>
#include <variant>
#include <optional>

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
	struct Private;
	Private *m;

	struct MKDIR {
	};
	struct RMDIR {
	};
	typedef std::variant<MKDIR, RMDIR> SftpCmd;
	struct SftpSimpleCommand;

	bool exec(ssh_session session, const char *command, std::function<bool (const char *, int)> writer);

	void close_scp();
	void clear_error();
public:
	EasySSH();
	~EasySSH();
	EasySSH(EasySSH const &) = delete;
	EasySSH &operator=(EasySSH const &) = delete;
	EasySSH(EasySSH &&) = delete;
	EasySSH &operator=(EasySSH &&) = delete;

	bool open(const char *host, int port, AuthVar authdata);
	void close();

	bool mkdir(std::string const &name);
	bool rmdir(std::string const &name);

	bool exec(char const *cmd, std::function<bool (const char *, int)> writer);
	bool push_file_scp(std::string const &path, std::function<int (char *ptr, int len)> reader, size_t size);
	bool pull_file_scp(std::function<bool (char const *ptr, int len)> writer);

	struct FileAttribute {
		std::string name;
		std::string longname;
		uint32_t flags = 0;
		uint8_t type = SSH_FILEXFER_TYPE_UNKNOWN;
		uint64_t size = 0;
		uint32_t uid = 0;
		uint32_t gid = 0;
		std::string owner;
		std::string group;
		uint32_t permissions = 0;
		uint64_t atime64 = 0;
		uint32_t atime = 0;
		uint32_t atime_nseconds = 0;
		uint64_t createtime = 0;
		uint32_t createtime_nseconds = 0;
		uint64_t mtime64 = 0;
		uint32_t mtime = 0;
		uint32_t mtime_nseconds = 0;
		std::string acl;
		uint32_t extended_count = 0;
		std::string extended_type;
		std::string extended_data;

		bool exists() const
		{
			return type != SSH_FILEXFER_TYPE_UNKNOWN;
		}
		bool isfile() const
		{
			return (type == SSH_FILEXFER_TYPE_REGULAR || type == SSH_FILEXFER_TYPE_SYMLINK);
		}
		bool isdir() const
		{
			return type == SSH_FILEXFER_TYPE_DIRECTORY;
		}
		bool islink() const
		{
			return type == SSH_FILEXFER_TYPE_SYMLINK;
		}
	};
	bool open_sftp();
	bool close_sftp();
	FileAttribute stat_sftp(const std::string &path);
	bool push_file_sftp(std::string const &path, std::function<int (char *ptr, int len)> reader);
	bool pull_file_sftp(std::string const &remote_path, std::function<int (char *ptr, int len)> writer);

	bool push_file(std::string const &path, std::function<int (char *ptr, int len)> reader);
	bool pull_file(std::string const &remote_path, std::function<int (char const *ptr, int len)> writer);
	struct stat stat(std::string const &path);

	class SFTP {
	private:
		EasySSH &ssh_;
	public:
		SFTP(EasySSH &ssh)
				: ssh_(ssh)
		{
		}
		~SFTP()
		{
			close();
		}
		bool open()
		{
			return ssh_.open_sftp();
		}
		void close()
		{
			ssh_.close_sftp();
		}
		bool push(const std::string &path, std::function<int (char *, int)> reader)
		{
			return ssh_.push_file_sftp(path, reader);
		}
		FileAttribute stat(const std::string &path)
		{
			return ssh_.stat_sftp(path);
		}

		bool push(std::string const &local_path, std::string remote_path);
	};
};


#endif // EASYSSH_H
