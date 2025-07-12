# Pr0t0x - Advanced Protocol Brute Force Tool

A powerful, multithreaded protocol brute force tool with advanced features for security testing and penetration testing.

## Features

- **Multiple Protocol Support**: FTP, SSH, HTTP/HTTPS, MySQL, PostgreSQL, SMTP, IMAP, SMB
- **Advanced Web Form Detection**: Intelligent HTML parsing with CSRF token detection
- **Wordlist Management**: Automatic download from GitHub repositories
- **Visual Effects**: Matrix-style console output with color coding
- **Threading**: Concurrent attack execution for improved performance
- **Signal Handling**: Graceful shutdown on interruption
- **Progress Tracking**: Real-time progress bars and status updates

## Supported Protocols

- **FTP**: File Transfer Protocol brute force
- **SSH**: Secure Shell authentication testing
- **HTTP/HTTPS**: Web form authentication with CSRF support
- **MySQL**: Database authentication testing
- **PostgreSQL**: Database authentication testing
- **SMTP**: Email server authentication
- **IMAP**: Email server authentication
- **SMB**: Windows file sharing authentication

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Boltsky/Pr0t0x.git
cd Pr0t0x
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the tool:
```bash
python Pr0t0x.py
```

## Dependencies

- `requests` - HTTP requests handling
- `colorama` - Cross-platform colored terminal text
- `paramiko` - SSH client implementation
- `pymysql` - MySQL database connector
- `psycopg2` - PostgreSQL adapter
- `tqdm` - Progress bar library
- `pysmb` - SMB/CIFS library (optional)

## Usage

Run the tool and follow the interactive menu:

```bash
python Pr0t0x.py
```

### Features

1. **Protocol Selection**: Choose from supported protocols
2. **Target Configuration**: Set target host and port
3. **Wordlist Management**: Download or import custom wordlists
4. **Threading attack**: Threading attacking for faster results
5. **Results Tracking**: Monitor progress and successful attempts

## Security Notice

⚠️ **Important**: This tool is designed for authorized security testing only. Use responsibly and only on systems you own or have explicit permission to test.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
