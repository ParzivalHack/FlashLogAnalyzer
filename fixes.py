def parse_logs(logfile):
    # Open the log file and read its contents
    with open(logfile, 'r') as f:
        log_contents = f.read()

    # Define regular expressions to extract relevant information from the log file
    ip_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    date_regex = r'\d{4}-\d{2}-\d{2}'
    time_regex = r'\d{2}:\d{2}:\d{2}'
    url_regex = r'\"(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE)\s([^\s]+)\s\w+/\d+\.\d+\"'
    status_regex = r'\s(\d{3})\s'
    user_agent_regex = r'\"([^\"]+)\"$'

    # Find all matches for each regular expression
    ips = re.findall(ip_regex, log_contents)
    dates = re.findall(date_regex, log_contents)
    times = re.findall(time_regex, log_contents)
    urls = re.findall(url_regex, log_contents)
    statuses = re.findall(status_regex, log_contents)
    user_agents = re.findall(user_agent_regex, log_contents)

    # Zip the matches into tuples for easier processing
    log_entries = list(zip(ips, dates, times, urls, statuses, user_agents))

    # Return the log entries as a list
    return log_entries
  
  
  
  
  
  def analyze_logs(log_entries, patterns=None):
    # Use Counter to count the occurrences of each field
    ip_counts = Counter(entry[0] for entry in log_entries)
    url_counts = Counter(entry[3] for entry in log_entries)
    status_counts = Counter(entry[4] for entry in log_entries)
    user_agent_counts = Counter(entry[5] for entry in log_entries)

    # If additional patterns were specified, extract them from the log entries and count their occurrences
    if patterns:
        pattern_counts = {}
        for pattern in patterns:
            regex = re.compile(pattern)
            matches = [regex.search(entry[5]) for entry in log_entries]
            matches = [match.group() for match in matches if match]
            pattern_counts[pattern] = Counter(matches)

    # Sort the fields by the number of occurrences in descending order
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_urls = sorted(url_counts.items(), key=lambda x: x[1],
