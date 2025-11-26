"""
LFIBay - Logger Module
Colored terminal output and progress tracking
"""

from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)


def print_banner():
    """
    Display ASCII art banner
    """
    banner = f"""{Fore.CYAN}
╦  ╔═╗╦╔╗ ╔═╗╦ ╦
║  ╠╣ ║╠╩╗╠═╣╚╦╝
╩═╝╚  ╩╚═╝╩ ╩ ╩ 
{Fore.YELLOW}Local File Inclusion Testing Tool
{Fore.RED}⚠️  Use only on authorized systems ⚠️{Style.RESET_ALL}
"""
    print(banner)


def log_info(msg):
    """
    Print info message in blue
    Args:
        msg: Message to print
    """
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def log_success(msg):
    """
    Print success message in green
    Args:
        msg: Message to print
    """
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def log_warning(msg):
    """
    Print warning message in yellow
    Args:
        msg: Message to print
    """
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def log_error(msg):
    """
    Print error message in red
    Args:
        msg: Message to print
    """
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def log_testing(msg):
    """
    Print testing message in cyan
    Args:
        msg: Message to print
    """
    print(f"{Fore.CYAN}[TESTING]{Style.RESET_ALL} {msg}")


def log_vulnerable(msg):
    """
    Print vulnerability found message in red/green
    Args:
        msg: Message to print
    """
    print(f"{Fore.GREEN}{Back.BLACK}[SUCCESS]{Style.RESET_ALL} {msg}")


def progress_bar(current, total, prefix='Progress', length=50):
    """
    Display progress bar
    Args:
        current: Current progress value
        total: Total value
        prefix: Prefix string
        length: Length of the progress bar
    """
    percent = 100 * (current / float(total))
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    
    print(f'\r{Fore.CYAN}{prefix}{Style.RESET_ALL} |{Fore.GREEN}{bar}{Style.RESET_ALL}| {percent:.1f}% ({current}/{total})', end='')
    
    if current == total:
        print()  # New line on completion


def print_separator():
    """
    Print a separator line
    """
    print(f"{Fore.WHITE}{'=' * 70}{Style.RESET_ALL}")


def print_header(text):
    """
    Print a header with formatting
    Args:
        text: Header text
    """
    print()
    print(f"{Fore.YELLOW}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{text.center(70)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'=' * 70}{Style.RESET_ALL}")
    print()


def print_findings_summary(findings):
    """
    Print a summary of findings
    Args:
        findings: List of finding dictionaries
    """
    if not findings:
        log_info("No vulnerabilities detected")
        return
    
    print_header("FINDINGS SUMMARY")
    
    # Count by confidence
    high = len([f for f in findings if f['confidence'] == 'high'])
    medium = len([f for f in findings if f['confidence'] == 'medium'])
    low = len([f for f in findings if f['confidence'] == 'low'])
    
    print(f"{Fore.GREEN}Total Vulnerable Payloads: {len(findings)}{Style.RESET_ALL}")
    print(f"  {Fore.RED}High Confidence: {high}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium Confidence: {medium}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Low Confidence: {low}{Style.RESET_ALL}")
    print()
    
    # Show top findings
    print(f"{Fore.CYAN}Top Findings:{Style.RESET_ALL}")
    for i, finding in enumerate(findings[:5], 1):
        confidence_color = {
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.CYAN
        }.get(finding['confidence'], Fore.WHITE)
        
        print(f"{i}. {confidence_color}[{finding['confidence'].upper()}]{Style.RESET_ALL} {finding['payload']}")
        print(f"   Evidence: {finding['evidence'][0] if finding['evidence'] else 'N/A'}")
    
    if len(findings) > 5:
        print(f"\n{Fore.CYAN}... and {len(findings) - 5} more findings{Style.RESET_ALL}")
    
    print()
