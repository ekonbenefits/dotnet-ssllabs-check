
# dotnet-ssllabs-check

Tool that will check ssllabs score api and cert expiration when provided a list of hosts.

```bash
Usage: ssllabs-check [options] <Hosts>

Arguments:
  Hosts                    Hosts to check SSL Grades and Validity

Options:
  -?|-h|--help             Show help information
  -o|--output <DIRECTORY>  Output Directory for optional json data [Default: don't write out data]
  --emoji                  Use emoji's when outputing to console
```

## Features

- Clearly Displays time to expiration for leaf certificates (if RSA and EC are both served both are listed).
- Highlights expiring certificates if 90 Days, if certificate validatity period is 90 days or under then uses 30 days.
- Shows SSL Grade per Host and IP address combo. 
- Error Codes types are combined for exit code with bitwise or.
