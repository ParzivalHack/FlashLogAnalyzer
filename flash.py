import tkinter as tk
from tkinter import filedialog, messagebox
import re
from collections import Counter
import os

# Define the functions for parsing and analyzing log files
def parse_logs(logfile):
    # Open the log file and read its contents
    with open(logfile, 'r') as f:
        log_contents = f.read()

    # Define regular expressions to extract relevant information from the log file
    ip_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    date_regex = r'\d{4}-\d{2}-\d{2}'
    time_regex = r'\d{2}:\d{2}:\d{2}'

    # Find all matches for each regular expression
    ips = re.findall(ip_regex, log_contents)
    dates = re.findall(date_regex, log_contents)
    times = re.findall(time_regex, log_contents)

    # Zip the matches into tuples for easier processing
    log_entries = list(zip(ips, dates, times))

    # Return the log entries as a list
    return log_entries

def analyze_logs(log_entries, patterns=None):
    # Use Counter to count the occurrences of each IP address
    ip_counts = Counter(entry[0] for entry in log_entries)

    # If additional patterns were specified, extract them from the log entries and count their occurrences
    if patterns:
        pattern_counts = {}
        for pattern in patterns:
            regex = re.compile(pattern)
            matches = [regex.search(entry[2]) for entry in log_entries]
            matches = [match.group() for match in matches if match]
            pattern_counts[pattern] = Counter(matches)

    # Sort the IP addresses by the number of occurrences in descending order
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Return the sorted IP addresses and their corresponding occurrence counts, as well as the pattern counts (if any)
    if patterns:
        return sorted_ips, pattern_counts
    else:
        return sorted_ips

def analyze_logs_gui():
    # Create a new window
    window = tk.Tk()

    # Define a function for opening log files
    def open_file():
        filename = filedialog.askopenfilename(initialdir='/', title='Select file', filetypes=(('Text files', '*.txt'), ('All files', '*.*')))
        if filename:
            filename_entry.delete(0, tk.END)
            filename_entry.insert(0, filename)
            analyze_button.config(state=tk.NORMAL)

    # Define a function for analyzing log files
    def analyze_file():
        logfile = filename_entry.get()
        if not logfile:
            messagebox.showerror('Error', 'Please select a log file')
            return
        try:
            log_entries = parse_logs(logfile)
        except Exception as e:
            messagebox.showerror('Error', f'Error parsing log file: {str(e)}')
            return
        
        # If additional patterns were specified, prompt the user to enter them
        patterns = None
        if additional_patterns.get():
            pattern_string = additional_patterns.get().strip()
            if pattern_string:
                patterns = pattern_string.split(',')
                patterns = [pattern.strip() for pattern in patterns]

        # Analyze the log entries
        if patterns:
            results_label.config(text='Analyzing log file (with additional patterns)...')
            security_incidents, pattern_counts = analyze_logs(log_entries, patterns)
        else:
            results_label.config(text='Analyzing log file...')
            security_incidents = analyze_logs(log_entries)
# Display the results
        results_text.delete(1.0, tk.END)
        if patterns:
            for pattern in patterns:
                results_text.insert(tk.END, f'{pattern}:\n')
                for match, count in pattern_counts[pattern].most_common():
                    results_text.insert(tk.END, f'  {match}: {count}\n')
        results_text.insert(tk.END, '\nIP addresses:\n')
        for ip, count in security_incidents:
            results_text.insert(tk.END, f'  {ip}: {count}\n')
    
    # Define the GUI widgets
    filename_label = tk.Label(window, text='Log file:')
    filename_entry = tk.Entry(window)
    browse_button = tk.Button(window, text='Browse', command=open_file)
    additional_patterns_label = tk.Label(window, text='Additional patterns (comma-separated):')
    additional_patterns = tk.Entry(window)
    analyze_button = tk.Button(window, text='Analyze', command=analyze_file, state=tk.DISABLED)
    results_label = tk.Label(window, text='')
    results_text = tk.Text(window, height=20, width=80)

    # Arrange the GUI widgets using the grid layout manager
    filename_label.grid(row=0, column=0, sticky=tk.E)
    filename_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E)
    browse_button.grid(row=0, column=3, sticky=tk.W)
    additional_patterns_label.grid(row=1, column=0, sticky=tk.E)
    additional_patterns.grid(row=1, column=1, columnspan=2, sticky=tk.W+tk.E)
    analyze_button.grid(row=1, column=3, sticky=tk.W)
    results_label.grid(row=2, column=0, sticky=tk.W)
    results_text.grid(row=3, column=0, columnspan=4)

    # Run the main event loop
    window.mainloop()

# Run the GUI
analyze_logs_gui()
