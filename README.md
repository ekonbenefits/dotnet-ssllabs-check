
# dotnet-ssllabs-check [![Nuget](https://img.shields.io/nuget/v/dotnet-ssllabs-check.svg)](https://www.nuget.org/packages/dotnet-ssllabs-check/)

Tool that will check ssllabs score api and cert expiration when provided a list of hosts.

## Notice
 
This is an Unofficial tool, using the [SSL Labs API v3](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md). See the SSL Labs [terms of use](https://www.ssllabs.com/about/terms.html). This tool works by
sending assessment requests to remote SSL Labs servers and that information will be shared with SSL Labs.

## Requirements

[.net Core v2.1 on Windows, Mac, or Linux](https://dotnet.microsoft.com/download/dotnet-core)

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
  --hostfile <PATH>        Retreive list of hostnames from file to check (one host per line, # preceding comments)
  --emoji                  Show emoji when outputing to console
```

## Features

- Clearly displays time to expiration for leaf certificates (if RSA and EC are both served then both are listed).
- Highlights expiring certificates if 90 Days, if original certificate validatity period is 90 days or under (Let's Encrypt) then uses 30 days.
- Shows SSL Grade per Host and IP address combo. 
- Error Codes types are combined for exit code with bitwise or.
- Runs requests in parallel when under api limits, but writes to console in order of scan finishing first.

## Example Standard Output

```bash
dotnet-ssllabs-check v2.0.0.0 - Unofficial Client - (engine:1.35.1) (criteria:2009p)

This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions: https://www.ssllabs.com/about/terms.html

Started: 7/17/2019 2:05:20 PM

Hostnames to Check:
 ekonbenefits.com
 myekon.com

-- 1 of 2 --- 00:00:06.8577868 --
ekonbenefits.com:
  Certificate #1 EC 256 bit:
    SAN: ekonbenefits.com, www.ekonbenefits.com
    Expires: 169 days from today
  Certificate #2 RSA 2048 bit:
    SAN: www.ekonbenefits.com, ekonbenefits.com
    Expires: 169 days from today
  Endpoint '12.110.225.243':
    Grade: A+
  Details:
    https://www.ssllabs.com/ssltest/analyze.html?d=ekonbenefits.com

-- 2 of 2 --- 00:00:28.6695682 --
myekon.com:
  Certificate #1 RSA 2048 bit:
    SAN: myekon.com, www.myekon.com
    Expires: 59 days from today
  Endpoint '12.110.225.243':
    Grade: A
  Details:
    https://www.ssllabs.com/ssltest/analyze.html?d=myekon.com

Completed: 7/17/2019 2:05:49 PM
All Clear.
```
