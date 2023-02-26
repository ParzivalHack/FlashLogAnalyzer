import tkinter as tk
from tkinter import filedialog
import re

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
    log_entries = zip(ips, dates, times)

    # Return the log entries as a list
    return list(log_entries)

def analyze_logs(log_entries):
    # Define a dictionary to store the number of occurrences for each IP address
    ip_counts = {}

    # Iterate over each log entry and count the number of occurrences for each IP address
    for entry in log_entries:
        ip_address = entry[0]
        if ip_address in ip_counts:
            ip_counts[ip_address] += 1
        else:
            ip_counts[ip_address] = 1

    # Sort the IP addresses by the number of occurrences in descending order
    sorted_ips = sorted(ip_counts, key=ip_counts.get, reverse=True)

    # Return the sorted IP addresses and their corresponding occurrence counts
    return [(ip, ip_counts[ip]) for ip in sorted_ips]

# Define the function for the GUI
def analyze_logs_gui():
    # Create a new window
    window = tk.Tk()

    # Define a function for opening log files
    def open_file():
        filename = filedialog.askopenfilename(initialdir='/', title='Select file', filetypes=(('Text files', '*.txt'), ('All files', '*.*')))
        filename_entry.delete(0, tk.END)
        filename_entry.insert(0, filename)

    # Define a function for analyzing log files
    def analyze_file():
        logfile = filename_entry.get()
        log_entries = parse_logs(logfile)
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
    analyze_button = tk.Button(window, text='Analyze', command=analyze_file)
    analyze_button.grid(row=1, column=1)

    window.mainloop()
    
