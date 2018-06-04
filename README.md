Evaluate an HTTP request's client address like Apache httpd's mod_remoteip or
Nginx's realip module.

For an event like this...
```ruby
{
  "remote_addr" => "10.1.1.1"
  "x_fwd_for" => ["1.2.3.4", "10.2.2.2"]
}
```

...an example configuration looks like so:
```ruby
filter {
  real_ip {
    remote_address_field => "remote_addr"
    x_forwarded_for_field => "x_fwd_for"
    trusted_networks => [
      "10.0.0.0/8",
      "192.168.0.0/16"
    ]
  }
}
```
This will evaluate the real client IP, writing it to a new field "realip".
For above example event that would be "1.2.3.4"

Often web servers don't provide the value of the X-Forwarded-For header as
an array. For ease of use the real_ip plugin provides capabilities to parse
such a comma-separated string. To enable this feature, use the
`x_forwarded_for_is_string` option.

For an event like this...
```ruby
{
  "remote_addr" => "10.1.1.1"
  "x_fwd_for" => "1.2.3.4, 10.2.2.2"
}
```

...an example configuration looks like so:
```ruby
filter {
  real_ip {
    remote_address_field => "remote_addr"
    x_forwarded_for_field => "x_fwd_for"
    x_forwarded_for_is_string => true
    trusted_networks => [
      "10.0.0.0/8",
      "192.168.0.0/16"
    ]
  }
}
```

In case the plugin fails to evaluate the real client IP, it will add a tag to
the event, by default `_real_ip_lookup_failure`.
The plugin will fail if one of below it true:
* The `remote_address` field is absent.
* The `remote_address` field doesn't contain an IP address.
* The filter is configured using `x_forwarded_for_is_string = true`, but the
`x_forwarded_for` field isn't a string.
* The `x_forwarded_for` field contains anything other that IP addresses.

#### Configuration
##### remote_address_field
* type: string
* default: `""`

Name of the field that contains the layer 3 remote IP address

##### x_forwarded_for_field
* type: string
* default: `""`

Name of the field that contains the X-Forwarded-For header value

##### x_forwarded_for_is_string
* type: boolean
* default: `false`

Specifies whether the `x_forwarded_for_field` contains a comman-separated
string instead of an array.

##### trusted_networks
* type: array
* default: `[]`

A list of trusted networks addresses. Be sure that you only specify
addresses that you trust will correctly manipulate the X-Forwarded-For
header.

##### target_field
* type: string
* default: `"real_ip"`

Name of the field that this plugin will write the evaluated real client IP
address to.

##### tags_on_failure
* type: array
* default: `["_real_ip_lookup_failure"]`

In case of error during evaluation, these tags will be set.
