# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"

# Evaluate an HTTP request's client address like Apache httpd's mod_remoteip or
# Nginx's realip module.
#
#
# For an event like this...
# [source,ruby]
#     {
#       "remote_addr" => "10.1.1.1"
#       "x_fwd_for" => ["1.2.3.4", "10.2.2.2"]
#     }
#
# ...an example configuration looks like so:
# [source,ruby]
#     filter {
#       real_ip {
#         remote_address_field => "remote_addr"
#         x_forwarded_for_field => "x_fwd_for"
#         trusted_networks => [
#           "10.0.0.0/8",
#           "192.168.0.0/16"
#         ]
#       }
#     }
# This will evaluate the real client IP, writing it to a new field "realip".
# For above example event that would be "1.2.3.4"
#
# Often web servers don't provide the value of the X-Forwarded-For header as
# an array. For ease of use the real_ip plugin provides capabilities to parse
# such a comma-separated string. To enable this feature, use the
# `x_forwarded_for_is_string` option.
#
# For an event like this...
# [source,ruby]
#     {
#       "remote_addr" => "10.1.1.1"
#       "x_fwd_for" => "1.2.3.4, 10.2.2.2"
#     }
#
# ...an example configuration looks like so:
# [source,ruby]
#     filter {
#       real_ip {
#         remote_address_field => "remote_addr"
#         x_forwarded_for_field => "x_fwd_for"
#         x_forwarded_for_is_string => true
#         trusted_networks => [
#           "10.0.0.0/8",
#           "192.168.0.0/16"
#         ]
#       }
#     }
#
# In case the plugin fails to evaluate the real client IP, it will add a tag to
# the event, by default `_real_ip_lookup_failure`.
# The plugin will fail if one of below it true:
# * The `remote_address` field is absent.
# * The `remote_address` field doesn't contain an IP address.
# * The filter is configured using `x_forwarded_for_is_string = true`, but the
# `x_forwarded_for` field isn't a string.
# * The `x_forwarded_for` field contains anything other that IP addresses.
#
# ==== Evaluation behavior ====
# The plugin checks whether the `remote_address_field` is trusted, if not, it
# will be written to `target_field`, and evaluation ends.
#
# Otherwise each IP in the `x_forwarded_for_field` is checked, from right to
# left until an untrusted IP is encountered, which will be written to
# `target_field` and evaluation ends at that point.
#
# In case `remote_address_field` and all IPs in `x_forwarded_for_field` are
# trusted, the left-most IP of the `x_forwarded_for_field` is written to
# `target_field`.
#
class LogStash::Filters::RealIp < LogStash::Filters::Base
  config_name "real_ip"

  # Name of the field that contains the layer 3 remote IP address
  config :remote_address_field, :validate => :string, :default => ""

  # Whether to check the remote address against the list of trusted networks.
  # If set to false and an error is encountered while evaluating
  # x_forwarded_for, the filter will fail.
  config :check_remote_address, :validate => :boolean, :default => true

  # Name of the field that contains the X-Forwarded-For header value
  config :x_forwarded_for_field, :validate => :string, :default => ""

  # Specifies whether the `x_forwarded_for_field` contains a comman-separated
  # string instead of an array.
  config :x_forwarded_for_is_string, :validate => :boolean, :default => false

  # A list of trusted networks addresses. Be sure that you only specify
  # addresses that you trust will correctly manipulate the X-Forwarded-For
  # header.
  config :trusted_networks, :validate => :array, :default => []

  # Name of the field that this plugin will write the evaluated real client IP
  # address to.
  config :target_field, :validate => :string, :default => "real_ip"

  # writes all valid IPs found in the x_forwarded_for header to this field
  config :x_forwarded_for_target, :validate => :string, :default => ""

  # In case any IPs processed are invalid IP addresses,
  # write all of them as one string to the field specified.
  config :target_on_invalid_ip, :validate => :string, :default => ""

  # In case any IPs processed are invalid IP addresses, these tags will be set.
  config :tags_on_invalid_ip, :valudate => :array, :default => ["_real_ip_invalid_ip"]

  # In case of error during evaluation, these tags will be set.
  config :tags_on_failure, :validate => :array, :default => ["_real_ip_lookup_failure"]

  public
  def register
    if @check_remote_address and @remote_address_field.length < 1
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "real_ip",
        :error => "The configuration option 'remote_address_field' must be a non-zero length string if 'check_remote_address' is set to true"
      )
    end

    if @x_forwarded_for_field.length < 1
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "real_ip",
        :error => "The configuration option 'x_forwarded_for_field' must be a non-zero length string"
      )
    end

    @trusted_networks.map! {|e| IPAddr.new(e)}
    @need_all = x_forwarded_for_target.length > 0
  end # def register

  private
  def match(address)
    # Try every combination of address and network, first match wins
    @trusted_networks.each do |n|
      @logger.debug? and @logger.debug("Checking IP inclusion", :address => address, :network => n)
      if n.include?(address)
        return true
      end
    end
    false
  end # def match

  public
  def filter(event)
    remote_addr = event.get(@remote_address_field) if @remote_address_field.length > 0
    fwdfor = event.get(@x_forwarded_for_field)

    if @check_remote_address
      # check for presence of remote_address_field
      if remote_addr == nil
        @logger.warn("remote_address_field missing from event", :event => event)
        @tags_on_failure.each {|tag| event.tag(tag)}
        return
      end
      # parse remote_address_field to IP
      begin
        remote_addr_ip = IPAddr.new(remote_addr)
      rescue ArgumentError => e
        @logger.warn("Invalid IP address in remote_addr field", :address => remote_addr, :event => event)
        @tags_on_failure.each {|tag| event.tag(tag)}
        return
      end
    else
      remote_addr_ip = nil
    end

    # check for presence of x_forwarded_for_field
    if fwdfor == nil
      if not @check_remote_address
        @logger.warn("x_forwarded_for_field missing from event", :event => event)
        @tags_on_failure.each {|tag| event.tag(tag)}
        return
      end

      @logger.debug? and @logger.debug("x_forwarded_for_field missing from event", :event => event)
      event.set(@target_field, remote_addr)
      filter_matched(event)
      return
    end

    # If remote_addr isn't trusted, we don't even have to look at the X-Forwarded-For header
    if @check_remote_address and match(remote_addr_ip) == false
      @logger.debug? and @logger.debug("remote_addr isn't trusted. evaluating to remote_addr", :address => remote_addr)
      event.set(@target_field, remote_addr)
      filter_matched(event)
      return
    end

    if @x_forwarded_for_is_string
      if not fwdfor.kind_of?(String)
        @logger.warn("x_forwarded_for_field isn't of type string", :event => event)
        @tags_on_failure.each {|tag| event.tag(tag)}
        return
      end

      fwdfor = fwdfor.gsub(/[ +]/, '').split(/,/)
    else
      # If there's only one IP in the X-Forwarded-For header, it's a string instead
      # of an Array.
      if not fwdfor.kind_of?(Array)
        @logger.debug? and @logger.debug("creating array from single string value xfwdfor", :xfwdfor => fwdfor)
        fwdfor = [fwdfor]
      end
    end

    # In case X-Forwarded-For header is set, but zero-length string
    if fwdfor.length == 0 or (fwdfor.length == 1 and fwdfor[0].length < 1)
      if not @check_remote_address
        @logger.warn("x_forwarded_for_field header was present but empty", :event => event)
        @tags_on_failure.each {|tag| event.tag(tag)}
        return
      end
      @logger.debug? and @logger.debug("x_forwarded_for_field header was present but empty, evaluate to remote_addr", :address => remote_addr)
      event.set(@target_field, remote_addr)
      filter_matched(event)
      return
    end

    found = false
    fatal = false
    target = []
    # check each IP in x_forwarded_for_field from last to first
    (fwdfor.length - 1).downto(0) do |i|
      begin
        ip = IPAddr.new(fwdfor[i])
      rescue ArgumentError => e
        @logger.warn("Invalid IP address", :address => fwdfor[i], :event => event)
        if not found
          @tags_on_failure.each {|tag| event.tag(tag)}
          fatal = true
        end
        @tags_on_invalid_ip.each {|tag| event.tag(tag)}
        next
      end

      target.unshift(ip.to_s()) if @need_all

      # return on the first non-match against our trusted networks
      if found == false and fatal == false and match(ip) == false
        event.set(@target_field, fwdfor[i])
        filter_matched(event)
        return if not @need_all
        found = true
      end
    end

    event.set(@x_forwarded_for_target, target) if @need_all

    if found == false and fatal == false
      # in case remote_addr and all x_forwarded_for IPs are trusted, use the
      # left-most IP from x_forwarded_for
      event.set(@target_field, fwdfor[0])
      filter_matched(event)
      return
    end

  end # def filter
end # class LogStash::Filters::RealIp
