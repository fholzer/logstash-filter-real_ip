# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/real_ip"

describe LogStash::Filters::RealIp do
  describe "Evaluates real IP correctly" do
    let(:config) do <<-CONFIG
      filter {
        real_ip {
          remote_address_field => "remote_addr"
          x_forwarded_for_field => "xfwdfor"
          trusted_networks => ["10.0.0.0/8", "192.168.0.0/16"]
        }
      }
    CONFIG
    end

    sample("dummy") do
      expect(subject).to include("tags")
      expect(subject.get('tags')).to include("_real_ip_lookup_failure")
    end

    sample("remote_addr" => "1.2.3.4") do
      if subject.get('tags') then expect(subject.get('tags')).not_to include("_real_ip_lookup_failure") end
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4") do
      expect(subject).not_to include("tags")
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('10.2.3.4')
    end

    sample("remote_addr" => "1.2.3.4", "xfwdfor" => "") do
      expect(subject).not_to include("tags")
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => "1.2.3.4") do
      expect(subject.get("tags")).to eq(nil)
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => ["1.2.3.4", "192.168.3.4"]) do
      expect(subject).not_to include("tags")
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end
  end

  describe "Evaluates real IP correctly with flat string xfwfor" do
    let(:config) do <<-CONFIG
      filter {
        real_ip {
          remote_address_field => "remote_addr"
          x_forwarded_for_field => "xfwdfor"
          x_forwarded_for_is_string => true
          trusted_networks => ["10.0.0.0/8", "192.168.0.0/16"]
        }
      }
    CONFIG
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => "1.2.3.4") do
      expect(subject.get("tags")).to eq(nil)
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => "1.2.3.4,+192.168.3.4") do
      expect(subject).not_to include("tags")
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => "1.2.3.4, 192.168.3.4,+ 192.168.4.5") do
      expect(subject).not_to include("tags")
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end
  end

  describe "Evaluates real IP correctly to non-default target field" do
    let(:config) do <<-CONFIG
      filter {
        real_ip {
          remote_address_field => "remote_addr"
          x_forwarded_for_field => "xfwdfor"
          target_field => "evaluated_ip"
          trusted_networks => ["10.0.0.0/8", "192.168.0.0/16"]
        }
      }
    CONFIG
    end

    sample("remote_addr" => "1.2.3.4") do
      expect(subject).not_to include("tags")
      expect(subject).to include("evaluated_ip")
      expect(subject.get('evaluated_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => "") do
      expect(subject).not_to include("tags")
      expect(subject).to include("evaluated_ip")
      expect(subject.get('evaluated_ip')).to eq('10.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => "1.2.3.4") do
      expect(subject.get("tags")).to eq(nil)
      expect(subject).to include("evaluated_ip")
      expect(subject.get('evaluated_ip')).to eq('1.2.3.4')
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => ["1.2.3.4", "192.168.3.4"]) do
      expect(subject).not_to include("tags")
      expect(subject).to include("evaluated_ip")
      expect(subject.get('evaluated_ip')).to eq('1.2.3.4')
    end
  end

  describe "works correctly with IPv6 in trusted_networks, x-fwd-for" do
    let(:config) do <<-CONFIG
      filter {
        real_ip {
          remote_address_field => "remote_addr"
          x_forwarded_for_field => "xfwdfor"
          trusted_networks => ["10.0.0.0/8", "2606:2800:220:1:248:1893:25c8:1946/120"]
        }
      }
    CONFIG
    end

    sample("remote_addr" => "10.2.3.4", "xfwdfor" => ["1.2.3.4", "2606:2800:220:1:248:1893:25c8:1946"]) do
      expect(subject).not_to include("tags")
      expect(subject).to include("real_ip")
      expect(subject.get('real_ip')).to eq('1.2.3.4')
    end
  end
end
