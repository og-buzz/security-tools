#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'

# Make net-ssh optional at load time so this file can be required as a library
# and so the CLI can print a friendly install hint instead of a backtrace.
begin
  require 'net/ssh'
  NET_SSH_AVAILABLE = true
rescue LoadError
  NET_SSH_AVAILABLE = false
end

# SshProbe: pre-authentication reconnaissance of an SSH service.
#
#   banner        Completes the SSH transport handshake and reads the server's
#                 version string (e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"). No
#                 authentication is attempted, so this is quiet on the target
#                 beyond the TCP connection itself.
#
#   auth_methods  Asks the server which authentication methods it offers. This
#                 DOES begin (and then abandon) authentication, so it normally
#                 records a failed login on the target. Opt-in only.
#
# This is intended for authorized security testing / inventory of hosts you
# administer. Only probe hosts you have permission to test.
class SshProbe
  Result = Struct.new(:host, :port, :banner, :auth_methods, :error, keyword_init: true)

  def initialize(port: 22, timeout: 5)
    @port = port
    @timeout = timeout
  end

  def probe(host, auth_methods: false)
    banner = read_banner(host)
    methods = auth_methods ? read_auth_methods(host) : nil
    Result.new(host: host, port: @port, banner: banner, auth_methods: methods, error: nil)
  rescue StandardError => e
    Result.new(host: host, port: @port, banner: nil, auth_methods: nil, error: e.message)
  end

  private

  # Reads the server version from the transport handshake. Pre-auth and quiet.
  def read_banner(host)
    transport = Net::SSH::Transport::Session.new(host, port: @port, timeout: @timeout)
    version = transport.server_version.version
    transport.close
    version
  end

  # Best-effort enumeration of offered auth methods.
  #
  # net-ssh does not expose the server's advertised method list through a stable
  # public API, so we start authentication with a throwaway user restricted to
  # the "none" method and read what the server reports back when it fails. On
  # most OpenSSH servers the rejected-methods list appears in the failure
  # message, e.g. "...(publickey,password)".
  #
  # NOTE: verify this against a real server on the target network (e.g. the
  # broker on .111) before relying on the parsed output; message formats vary by
  # net-ssh version and server. The banner grab above is the reliable default.
  def read_auth_methods(host)
    Net::SSH.start(
      host, 'nonexistent-probe-user',
      port: @port,
      timeout: @timeout,
      auth_methods: %w[none],
      non_interactive: true,
      number_of_password_prompts: 0,
      verify_host_key: :never
    )
    # Reaching here means "none" was accepted — an unauthenticated login.
    ['none (server allowed unauthenticated access!)']
  rescue Net::SSH::AuthenticationFailed => e
    parse_methods_from_message(e.message)
  end

  def parse_methods_from_message(msg)
    if (m = msg.match(/\(([^)]+)\)/))
      m[1].split(',').map(&:strip)
    else
      ["unknown (could not parse; raw: #{msg})"]
    end
  end
end

# --- CLI --------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { port: 22, auth_methods: false, timeout: 5, file: nil }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby ssh_probe.rb [options] <host> [host...]'
    o.on('-p', '--port PORT', Integer, 'SSH port (default 22)') { |v| options[:port] = v }
    o.on('-f', '--file FILE', 'Read hosts from FILE (one per line)') { |v| options[:file] = v }
    o.on('--auth-methods', 'Enumerate offered auth methods (LOGS a failed login on the target)') do
      options[:auth_methods] = true
    end
    o.on('-t', '--timeout SECONDS', Integer, 'Connection timeout seconds (default 5)') do |v|
      options[:timeout] = v
    end
    o.on('-h', '--help', 'Show this help') { puts o; exit }
  end
  parser.parse!

  hosts = ARGV.dup
  if options[:file]
    hosts.concat(File.readlines(options[:file], chomp: true).map(&:strip).reject(&:empty?))
  end

  if hosts.empty?
    warn parser
    exit 1
  end

  unless NET_SSH_AVAILABLE
    warn 'Error: the `net-ssh` gem is required. Install it with `gem install net-ssh` (or `bundle install`).'
    exit 2
  end

  probe = SshProbe.new(port: options[:port], timeout: options[:timeout])
  hosts.each do |host|
    r = probe.probe(host, auth_methods: options[:auth_methods])
    puts "\n#{r.host}:#{r.port}"
    if r.error
      puts "  error: #{r.error}"
      next
    end
    puts "  banner: #{r.banner}"
    puts "  auth methods: #{r.auth_methods.join(', ')}" if r.auth_methods
  end
  puts
end
