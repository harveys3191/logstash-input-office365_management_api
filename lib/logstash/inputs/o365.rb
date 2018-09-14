# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname
require "adal"
require "json"
require 'net/http'
require 'uri'

class LogStash::Inputs::O365 < LogStash::Inputs::Base
  config_name "O365"

  default :codec, "plain"

  # Fix for broken ruby ADAL
  module ADAL
   class TokenRequest
    module GrantType
     JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    end
   end
  end

  # Office 365 parameters
  config :client_id, :validate => :string, :required => true
  config :tenant_id, :validate => :string, :required => true
  config :tenant_domain, :validate => :string, :required => true
  config :resource, :validate => :string, :default => 'https://manage.office.com'
  config :public_thumbprint, :validate => :string, :required => true
  config :private_key, :validate => :path
  config :private_key_password, :validate => :path, :default => nil
  config :subscriptions, :validate => :array, :default => ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"]

  public
  def register
    @logger.info("Starting Office 365 Management API input...")
    @host = Socket.gethostname
    
    # ADAL supports four logging options: VERBOSE, INFO, WARN and ERROR.
    ADAL::Logging.log_level = ADAL::Logger::VERBOSE

  end # def register
  def get_token
    @logger.info("Generating access token...")

    pfx = OpenSSL::PKCS12.new(File.read(private_key), private_key_password)
    authority = ADAL::Authority.new(ADAL::Authority::WORLD_WIDE_AUTHORITY, tenant_domain)
    client_cred = ADAL::ClientAssertionCertificate.new(authority, client_id, pfx)
    result = ADAL::AuthenticationContext
          .new(ADAL::Authority::WORLD_WIDE_AUTHORITY, tenant_domain)
          .acquire_token_for_client(resource, client_cred)

    case result
     when ADAL::SuccessResponse
       puts 'Successfully authenticated with client credentials. Received access ' "token: #{result.access_token}."
       # Create global variable for reuse of Access Token
       $access_token = result.access_token
       $http_headers = {
        'Authorization' => "Bearer #{access_token}",
        'Content-Type' => 'application/x-www-form-urlencoded'
       }

     when ADAL::FailureResponse
       puts 'Failed to authenticate with client credentials. Received error: ' "#{result.error} and error description: #{result.error_description}."
       exit 1
    end
  end #def get_token

  def check_subscription
    @logger.info("Checking for proper subscriptions...")
    subscriptions.each do |sub|
      sub_uri = URI("https://manage.office.com/api/v1.0/#{tenant_id}/activity/feed/subscriptions/start?contentType=#{sub}")
      sub_http = Net::HTTP.new(sub_uri.host, sub_uri.port)
      sub_http.use_ssl = true
      sub_resp = http.post(sub_uri.request_uri, nil, http_headers)

      case sub_resp
       when Net::HTTPSuccess
         puts "Created subscription to #{sub} in tenant #{tenant_id}..."
       when Net::HTTPUnauthorized
         puts "Authentication Error Encountered: #{sub_resp.message}"
       when Net::HTTPServerError
         puts "Server Error Encountered: #{sub_resp.message}"
       else
         puts "Unknown Error Encountered: #{sub_resp.message}"
      end
    end
  end #def check_subscription

  def run(queue)
    # we can abort the loop if stop? becomes true
    while !stop?
      #event = LogStash::Event.new("message" => @message, "host" => @host)
      #decorate(event)
      #queue << event
      raise 'Error getting token' unless get_token().status == 0

      # because the sleep interval can be big, when shutdown happens
      # we want to be able to abort the sleep
      # Stud.stoppable_sleep will frequently evaluate the given block
      # and abort the sleep(@interval) if the return value is true
      Stud.stoppable_sleep(@interval) { stop? }
    end # loop
  end # def run

  def stop
    # nothing to do in this case so it is not necessary to define stop
    # examples of common "stop" tasks:
    #  * close sockets (unblocking blocking reads/accepts)
    #  * cleanup temporary files
    #  * terminate spawned threads
  end
end # class LogStash::Inputs::O365
