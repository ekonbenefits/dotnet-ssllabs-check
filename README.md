
# dotnet-ssllabs-check ![Nuget](https://img.shields.io/nuget/v/dotnet-ssllabs-check.svg)

Tool that will check ssllabs score api and cert expiration when provided a list of hosts.

## Notice
 
This is an Unofficial tool, using the [SSL Labs API v3](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md). See the SSL Labs [terms of use](https://www.ssllabs.com/about/terms.html). This tool works by
sending assessment requests to remote SSL Labs servers and that information will be shared with SSL Labs.


## Install

```bash
dotnet tool install --global dotnet-ssllabs-check
```

## Usage

```bash
dotnet-ssllabs-check

Unofficial SSL Labs Client

Usage: ssllabs-check [options] <hostname(s)>

Arguments:
  hostname(s)              Hostnames to check SSL Grades and Validity

Options:
  -?|-h|--help             Show help information
  -v|--version             Show version and service information
  -o|--output <DIRECTORY>  Output directory for json data [Default: does not write out data]
  --hostfile <PATH>        Retreive list of hostnames from file to check (one host per line)
  --emoji                  Show emoji when outputing to console
```

## Features

- Clearly displays time to expiration for leaf certificates (if RSA and EC are both served then both are listed).
- Highlights expiring certificates if 90 Days, if original certificate validatity period is 90 days or under (Let's Encrypt) then uses 30 days.
- Shows SSL Grade per Host and IP address combo. 
- Error Codes types are combined for exit code with bitwise or.
- Runs requests in parallel when under api limits, but writes to console when it has the data to do it.
