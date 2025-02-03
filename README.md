# genencap

> GENEVE encapsulate TCP or UDP packets

## Overview

This program reads packets from a network interface, GENEVE encapsulates them and sends them to a remote host.

## Usage

```bash
./genencap -i <interface> -r <destination IP addres> -p <destination port>
```

```bash
./genencap -h
```

## Install

```bash
go install github.com/mlbright/genencap@latest
```

## Build

```bash
go build
```
