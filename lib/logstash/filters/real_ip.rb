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

  # In case of error during evaluation, these tags will be set.
  config :tags_on_failure, :validate => :array, :default => ["_real_ip_lookup_failure"]

  public
  def register
    if @remote_address_field.length < 1
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "real_ip",
        :error => "The configuration option 'remote_address_field' must be a non-zero length string"
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
  end # def register

  private
  def match(address)
    # Try every combination of address and network, first match wins
    @trusted_networks.each do |n|
      @logger.debug("Checking IP inclusion", :address => address, :network => n)
      if n.include?(address)
        true
        return
      end
    end
    false
  end # def match

  public
  def filter(event)
    remote_addr = event.get(@remote_address_field)
    fwdfor = event.get(@x_forwarded_for_field)

    # check for presence of remote_address_field
    if remote_addr == nil
      @logger.warn("remote_address_field missing from event", :event => event)
      @tags_on_failure.each {|tag| event.tag(tag)}
      return
    end

    # check for presence of x_forwarded_for_field
    if fwdfor == nil
      @logger.info("x_forwarded_for_field missing from event", :event => event)
      event.set(@target_field, remote_addr)
      filter_matched(event)
      return
    end


    begin
      ip = IPAddr.new(remote_addr)
    rescue ArgumentError => e
      @logger.warn("Invalid IP address in remote_addr field", :address => remote_addr, :event => event)
      @tags_on_failure.each {|tag| event.tag(tag)}
      return
    end

    # If remote_addr isn't trusted, we don't even have to look at the X-Forwarded-For header
    if match(ip) == false
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

    # in case x_forwarded_for is empty
    if fwdfor.length == 0
      event.set(@target_field, remote_addr)
      filter_matched(event)
      return
    end

    # In case X-Forwarded-For header is set, but zero-length string
    if fwdfor.length == 1 and fwdfor[0].length < 1
      @logger.debug? and @logger.debug("xfwdfor header was present but empty, evaluate to remote_addr", :address => remote_addr)
      event.set(@target_field, remote_addr)
      filter_matched(event)
      return
    end

    # check each IP in x_forwarded_for_field from last to first
    (fwdfor.length - 1).downto(0) do |i|
      begin
        ip = IPAddr.new(fwdfor[i])
      rescue ArgumentError => e
        @logger.warn("Invalid IP address", :address => fwdfor[i], :event => event)
        @tags_on_failure.each {|tag| event.tag(tag)}
        return
      end

      # return on the first non-match against our trusted networks
      if match(ip) == false
        event.set(@target_field, fwdfor[i])
        filter_matched(event)
        return
      end
    end

    # in case remote_addr and all x_forwarded_for IPs are trusted, use the
    # left-most IP from x_forwarded_for
    event.set(@target_field, fwdfor[0])
    filter_matched(event)
    return

  end # def filter
end # class LogStash::Filters::RealIp
