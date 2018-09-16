# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname
require "json"
require 'net/http'
require 'uri'
require 'adal'

# Using this input you can receive activities from the Office 365 Management API
# ==== Security
# This plugin utilizes certificate authentication with the Office 365 Management API
# to generate an access token, which is then used for all subsequent API activities.
# If the token expires, the plugin will request a new token automatically.
# All communication for this plugin is encrypted by SSL/TLS communication.

class LogStash::Inputs::Office365ManagementApi < LogStash::Inputs::Base
  config_name "office365_management_api"

  # Codec used to decode the incoming data.
  # This codec will be used as a fall-back if the content-type
  # is not found in the "additional_codecs" hash
  default :codec, "json"

  # Fix for broken ruby ADAL
  #module ADAL
  # class TokenRequest
  #  module GrantType
  #   JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  #  end
  # end
  #end

  # Client ID generated through your custom application in Azure AD
  # https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps
  config :client_id, :validate => :string, :required => true
  
  # Client Secret generated through your custom application in Azure AD
  # https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps
  config :client_secret, :validate => :string, :required => true

  # Tenant ID/Directory ID of your Office 365 tenant
  # https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties
  config :tenant_id, :validate => :string, :required => true

  # Your Office 365 tenant domain, ie. yourdomain.onmicrosoft.com
  config :tenant_domain, :validate => :string, :required => true

  # Resource you are requesting access to. This defaults to https://manage.office.com and shouldn't change unless necessary.
  config :resource, :validate => :string, :default => 'https://manage.office.com'

  # PFX Private key for your Application Certificate you created
  config :private_key, :validate => :path

  # Private key password if one was used
  config :private_key_password, :validate => :string, :default => nil

  # Activity subscriptions you want to monitor
  # These can be one or many of:
  # Audit.AzureActiveDirectory
  # Audit.Exchange
  # Audit.Sharepoint
  # Audit.General
  # DLP.All
  config :subscriptions, :validate => :array, :default => ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"]

  public
  def register
    @logger.info("Starting Office 365 Management API input...")
    @host = Socket.gethostname
    @last_check = Time.now
    @interval = 300
    #ADAL::Logging.log_level = ADAL::Logger::VERBOSE
  end # def register

  def run(queue)
    # we can abort the loop if stop? becomes true
    while !stop?
      start = Time.now
      
      @logger.info("Retrieving access token...")
      auth_ctx = ADAL::AuthenticationContext.new(ADAL::Authority::WORLD_WIDE_AUTHORITY, @tenant_id)
      client_cred = ADAL::ClientCredential.new(@client_id, @client_secret)
      result = auth_ctx.acquire_token_for_client(@resource, client_cred)

      case result
       when ADAL::SuccessResponse
        @logger.info("Successfully authenticated with client credentials...")
        @access_token = result.access_token
        @http_headers = {
          'Authorization' => "Bearer #{@access_token}",
          'Content-Type' => 'application/x-www-form-urlencoded'
        }
       when ADAL::FailureResponse
        @logger.error("Failed to authenticate with client credentials. Received error: #{result.error} and error description: #{result.error_description}")
        break
      end

      # Start Subscription Configuration
      subscriptions.each do |sub|
        sub_uri = URI("https://manage.office.com/api/v1.0/#{@tenant_id}/activity/feed/subscriptions/start?contentType=#{sub}")
        sub_http = Net::HTTP.new(sub_uri.host, sub_uri.port)
        sub_http.use_ssl = true
        sub_resp = sub_http.post(sub_uri.request_uri, nil, @http_headers)
        
        # Responses
        # AF20024 - Already Subscribed
        #
        case sub_resp
         when Net::HTTPSuccess
           @logger.info("Created subscription to #{sub} in tenant #{@tenant_id}...")
         when Net::HTTPUnauthorized
           @logger.info("Authentication Error Encountered: #{sub_resp.message} - #{sub_resp.body}")
         when Net::HTTPServerError
           @logger.info("Server Error Encountered: #{sub_resp.message} - #{sub_resp.body}")
         else
           sub_json = JSON.parse(sub_resp.body)
           if sub_json['error']['code'] = "AF20024"
             @logger.info("Already Subscribed to #{sub}, no action needed")
           else
             @logger.error("Unknown Error Encountered: #{sub_resp.message} - #{sub_resp.body}")
           end
        end
      end

      # Start message pulls
      subscriptions.each do |subtag|
        @sub_tag = subtag
        end_time = Time.now.strftime("%FT%H:%M") 
        next_time = Time.now - @interval
        start_time = next_time.strftime("%FT%H:%M")
        @logger.info("Sub: #{subtag} - Start time: #{start_time} - End Time: #{end_time} - URI: https://manage.office.com/api/v1.0/#{@tenant_id}/activity/feed/subscriptions/content?contentType=#{subtag}&startTime=#{start_time}&endTime=#{end_time}")
        msg_uri = URI("https://manage.office.com/api/v1.0/#{@tenant_id}/activity/feed/subscriptions/content?contentType=#{subtag}&startTime=#{start_time}&endTime=#{end_time}")
        @msg_http = Net::HTTP.new(msg_uri.host, msg_uri.port)
        @msg_http.use_ssl = true
        @msg_resp = @msg_http.get(msg_uri.request_uri, @http_headers)
        
        @logger.debug("Response from msg: #{@msg_resp.body}")

       msg_json = JSON.parse(@msg_resp.body)
       msg_json.each do |message|
         message_uri = URI(message['contentUri'])
         message_res = @msg_http.get(message_uri.request_uri + "?PublisherIdentifier=#{@tenant_id}", @http_headers)
         tmp_json = JSON.parse(message_res.body)
         tmp_json.each do |tmp_message|
           #event = LogStash::Event.new("message" => message_res.body, "host" => @host)
           event = LogStash::Event.new("message" => tmp_message.to_json, "host" => @host)
           decorate(event)
           event.set("event_type", @sub_tag)
           queue << event
         end
       end

        # TODO: Handle NextPageUri if it shows up in response headers
        #if @mesg_resp['NextPageUri'].nil?
        #  process_activity
        #else
        #  next_page = msg_resp['NextPageUri']
        #  process_activity
        #  @msg_resp = @msg_http.get(next_page + "?PublisherIdentifier=#{@tenant_id}", @http_headers)
        #end
      end
      
      # because the sleep interval can be big, when shutdown happens
      # we want to be able to abort the sleep
      # Stud.stoppable_sleep will frequently evaluate the given block
      # and abort the sleep(@interval) if the return value is true
      #Stud.stoppable_sleep(@interval) { stop? }
      sleep_for = @interval - (Time.now - start)
      @logger.info("Looping...")
      Stud.stoppable_sleep(sleep_for) { stop? } if sleep_for > 0
    end # loop
  end # def run

  def stop
    # nothing to do in this case so it is not necessary to define stop
    # examples of common "stop" tasks:
    #  * close sockets (unblocking blocking reads/accepts)
    #  * cleanup temporary files
    #  * terminate spawned threads
  end

end # class LogStash::Inputs::Office365ManagementApi
