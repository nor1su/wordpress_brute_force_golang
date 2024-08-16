This code is a Go-based utility for automating the attempt to authenticate on a website using a list of potential passwords (brute-force method). The program utilizes multi-threading and a pool of HTTP clients for concurrent execution of authentication requests. It supports automatic adjustment of the number of threads based on load and execution conditions.

### Features:
- **Parallel Password Testing**: Use of goroutines to asynchronously send authentication requests.
- **Configuration via Flags**: Ability to set the target URL, username, path to the password file, and number of threads through the command line.
- **Dynamic Thread Regulation**: Automatic adjustment of the number of threads based on current performance and network conditions.
- **Simple Result Handling**: Outputs successful login attempt and real-time process statistics.

### How to Use:
1. **Compile the program**:
   ```bash
   go build -o password_cracker
   ```
2. **Run the program**:
   ```bash
   ./password_cracker -url="http://example.com" -username="admin" -password-list="passwords.txt" -threads=auto
   ```
   Replace `http://example.com`, `admin`, `passwords.txt`, and `10` with the appropriate values.

### Command Line Parameters:
- `url`: URL of the target site for the attack.
- `username`: Username for which the login attempt is made.
- `password-list`: Path to the file containing a list of passwords.
- `threads`: Number of threads to use for authentication (can specify `auto` for automatic adjustment).

### Important Notes:
- **Security and Legality**: Use this tool only with the permission of the target resource owner. Unauthorized and illegal use may lead to legal liability.
- **Performance Optimization**: Performance may vary depending on network conditions and server capacity.

### Requirements:
- Go version 1.15 or higher.
- Access to the target server and rights to make network requests.

This README will help users understand and effectively utilize your program.
