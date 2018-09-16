# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/office365_management_api"
require "adal"

describe LogStash::Inputs::Office365ManagementApi do

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "interval" => 100 } }
  end

end
