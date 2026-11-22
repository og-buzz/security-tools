#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require 'rexml/document'
require 'open3'

# PortScanner: a thin, structured wrapper around the system `nmap`.
#
# It shells out to nmap with XML output (-oX -) and parses the result into
# plain Ruby structs. By default it uses a TCP connect scan (-sT), which needs
# no root privileges, and skips host discovery (-Pn) since callers typically
# already know the host is up (e.g. a discovered domain controller or a known
# broker address).
#
# Usable as a library (require this file and use PortScanner) or as a CLI.
class PortScanner
  # Ports relevant to AD/Windows infrastructure and MQTT brokers.
  DEFAULT_PORTS = [
    22,    # SSH
    88,    # Kerberos
    135,   # RPC endpoint mapper
    139,   # NetBIOS session service
    389,   # LDAP
    445,   # SMB
    636,   # LDAPS
    1883,  # MQTT
    3268,  # Global Catalog
    3269,  # Global Catalog over TLS
    3389,  # RDP
    5985,  # WinRM (HTTP)
    5986,  # WinRM (HTTPS)
    8883   # MQTT over TLS
  ].freeze

  Result = Struct.new(:host, :hostname, :ports, keyword_init: true)
  PortInfo = Struct.new(:port, :protocol, :state, :service, :product, :version, keyword_init: true)

  def initialize(ports: DEFAULT_PORTS, version_detection: false, nmap_path: 'nmap')
    @ports = ports
    @version_detection = version_detection
    @nmap_path = nmap_path
  end

  # Returns true if the configured nmap binary is runnable.
  def self.nmap_available?(nmap_path = 'nmap')
    _out, status = Open3.capture2e(nmap_path, '--version')
    status.success?
  rescue Errno::ENOENT
    false
  end

  # Scan one or more targets. Each target may be a hostname, an IP address, or a
  # CIDR range (nmap expands ranges itself). Returns an array of Result structs
  # for every host nmap reports on.
  def scan(*targets)
    raise ArgumentError, 'no targets given' if targets.flatten.empty?

    parse(run_nmap(targets.flatten))
  end

  private

  def run_nmap(targets)
    cmd = [@nmap_path, '-oX', '-', '-Pn']
    cmd << (@version_detection ? '-sV' : '-sT')
    cmd << '-p' << @ports.join(',')
    cmd.concat(targets)

    stdout, stderr, status = Open3.capture3(*cmd)
    unless status.success?
      raise "nmap exited with status #{status.exitstatus}: #{stderr.strip}"
    end

    stdout
  end

  def parse(xml)
    doc = REXML::Document.new(xml)
    results = []

    doc.elements.each('nmaprun/host') do |host_el|
      addr = host_el.elements["address[@addrtype='ipv4']"] ||
             host_el.elements["address[@addrtype='ipv6']"]
      next unless addr

      hostname_el = host_el.elements['hostnames/hostname']

      ports = []
      host_el.elements.each('ports/port') do |port_el|
        state = port_el.elements['state']&.attributes&.[]('state')
        next unless state == 'open'

        svc = port_el.elements['service']
        ports << PortInfo.new(
          port: port_el.attributes['portid'].to_i,
          protocol: port_el.attributes['protocol'],
          state: state,
          service: svc&.attributes&.[]('name'),
          product: svc&.attributes&.[]('product'),
          version: svc&.attributes&.[]('version')
        )
      end

      results << Result.new(
        host: addr.attributes['addr'],
        hostname: hostname_el&.attributes&.[]('name'),
        ports: ports.sort_by(&:port)
      )
    end

    results
  end
end

# --- CLI --------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { ports: PortScanner::DEFAULT_PORTS, version: false, file: nil }

  parser = OptionParser.new do |o|
    o.banner = <<~BANNER
      Usage: ruby port_scanner.rb [options] <target> [target...]
        target: hostname, IP, or CIDR (e.g. 192.168.1.111 or 192.168.1.0/24)
    BANNER
    o.on('-p', '--ports LIST', 'Comma-separated ports (default: AD/Windows + MQTT set)') do |v|
      options[:ports] = v.split(',').map { |s| s.strip.to_i }.reject(&:zero?)
    end
    o.on('-f', '--file FILE', 'Read targets from FILE (one per line)') { |v| options[:file] = v }
    o.on('--version-detection', 'Enable nmap -sV service/version detection (slower, noisier)') do
      options[:version] = true
    end
    o.on('-h', '--help', 'Show this help') { puts o; exit }
  end
  parser.parse!

  targets = ARGV.dup
  if options[:file]
    targets.concat(File.readlines(options[:file], chomp: true).map(&:strip).reject(&:empty?))
  end

  if targets.empty?
    warn parser
    exit 1
  end

  unless PortScanner.nmap_available?
    warn 'Error: `nmap` not found on PATH. Install it (e.g. `apt install nmap` / `brew install nmap`).'
    exit 2
  end

  scanner = PortScanner.new(ports: options[:ports], version_detection: options[:version])
  begin
    results = scanner.scan(*targets)
  rescue StandardError => e
    warn "Scan failed: #{e.message}"
    exit 1
  end

  if results.empty?
    puts 'No hosts responded (or none reported open ports).'
  else
    results.each do |r|
      label = r.hostname ? "#{r.host} (#{r.hostname})" : r.host
      puts "\n#{label}"
      if r.ports.empty?
        puts '  no open ports in scanned set'
      else
        r.ports.each do |p|
          svc = [p.service, p.product, p.version].compact.join(' ')
          puts "  #{p.port}/#{p.protocol}  open#{svc.empty? ? '' : "  #{svc}"}"
        end
      end
    end
    puts
  end
end
