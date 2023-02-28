import tkinter as tk
from tkinter import filedialog
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

def analyze_logs(log_entries):
    # Use Counter to count the occurrences of each IP address
    ip_counts = Counter(entry[0] for entry in log_entries)

    # Sort the IP addresses by the number of occurrences in descending order
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Return the sorted IP addresses and their corresponding occurrence counts
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
        security_incidents = analyze_logs(log_entries)

        # Create a new window to display the results
        results_window = tk.Toplevel(window)
        results_window.title('Security Incidents')

        # Create a label to display the results
        results_label = tk.Label(results_window, text='IP address\tOccurrences')
        results_label.pack()

        for incident in security_incidents:
            ip_label = tk.Label(results_window, text='{}\t{}'.format(incident[0], incident[1]))
            ip_label.pack()

    # Create a label and entry box for selecting a log file
    filename_label = tk.Label(window, text='Log file:')
    filename_label.grid(row=0, column=0)

    filename_entry = tk.Entry(window)
    filename_entry.grid(row=0, column=1)

    # Create a button for selecting a log file
    select_button = tk.Button(window, text='Select', command=open_file)
    select_button.grid(row=0, column=2)

    # Create a button for analyzing the log file
    analyze_button = tk.Button(window, text='Analyze', command=analyze_file, state=tk.DISABLED)
    analyze_button.grid(row=1, column=1)
    
    window.mainloop()
    
analyze_logs_gui()
