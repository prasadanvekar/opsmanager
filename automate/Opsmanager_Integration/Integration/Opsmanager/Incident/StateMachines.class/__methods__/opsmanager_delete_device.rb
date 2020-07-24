=begin
 opsmanager_add_device.rb

 Author: Prasad A prasad.a@cloudfx.com

 Description: This method creates a ServiceNow Incident Record via REST API
-------------------------------------------------------------------------------
   Copyright 2020 Cloudfx.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-------------------------------------------------------------------------------
=end
def log(level, msg, update_message = false)
  $evm.log(level, "#{msg}")
  @task.message = msg if @task && (update_message || level == 'error')
end

def call_opsmanager(action, tablename='deleteDevice', body=nil)
  require 'rest_client'
  require 'json'
  require 'base64'

  servername = nil || $evm.object['servername']
  username   = nil   || $evm.object['username']
  password   = nil   || $evm.object.decrypt('password')
  apiKey     = nil   || $evm.object['apiKey']
  url = "https://#{servername}/api/json/discovery/#{tablename}"

  params = {
    :method=>action, :url=>url,
    :headers=>{ :content_type=>:json, :accept=>:json, :authorization => "Basic #{Base64.strict_encode64("#{username}:#{password}")}" }
  }
  params[:payload] = body.to_json
  log(:info, "Calling url: #{url} action: #{action} payload: #{params}")

  RestClient.proxy = $evm.object['proxy_url'] unless $evm.object['proxy_url'].nil?

  opsmgr_response = RestClient::Request.new(params).execute
  log(:info, "response headers: #{opsmgr_response.headers}")
  log(:info, "response code: #{opsmgr_response.code}")
  log(:info, "response: #{opsmgr_response}")
  opsmgr_response_hash = JSON.parse(opsmgr_response)
  return opsmgr_response_hash['result']
end

def get_hostname
  hostname = @object.hostnames.first rescue nil
  hostname.blank? ? (return @object.name) : (return hostname)
end

def build_payload
  comments += "deviceName: #{get_hostname}\n"
  (body_hash ||= {})['comments'] = comments
  return body_hash
end

begin
  $evm.root.attributes.sort.each { |k, v| log(:info, "Root:<$evm.root> Attribute - #{k}: #{v}")}

  case $evm.root['vmdb_object_type']
  when 'vm', 'miq_provision'
    @task   = $evm.root['miq_provision']
    @object = @task.try(:destination) || $evm.root['vm']
  when 'automation_task'
    @task   = $evm.root['automation_task']
    @object = $evm.vmdb(:vm).find_by_name($evm.root['vm_name']) ||
      $evm.vmdb(:vm).find_by_id($evm.root['vm_id'])
  end

  exit MIQ_STOP unless @object

  body_hash = build_payload

  # object_name = 'Event' means that we were triggered from an Alert
  if $evm.root['object_name'] == 'Event'
    log(:info, "Detected Alert driven event")
    body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['miq_alert_description']}"
  elsif $evm.root['ems_event']
    # ems_event means that were triggered via Control Policy
    log(:info, "Detected Policy driven event")
    log(:info, "Inspecting $evm.root['ems_event']:<#{$evm.root['ems_event'].inspect}>")
    body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['ems_event'].event_type}"
  else
    unless $evm.root['dialog_miq_alert_description'].nil?
      log(:info, "Detected service dialog driven event")
      # If manual creation add dialog input notes to body_hash
      body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['dialog_miq_alert_description']}"
    else
      log(:info, "Detected manual driven event")
      # If manual creation add default notes to body_hash
      body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - Incident manually created"
    end

    # call opsmgr
    log(:info, "Calling Opsmanager: add device information: #{body_hash.inspect}")
    opsmgr_result = call_opsmanager(:post, 'deleteDevice', body_hash)

    log(:info, "opsmgr_result: #{opsmgr_result.inspect}")
    log(:info, "number: #{opsmgr_result['number']}")
    log(:info, "sys_id: #{opsmgr_result['sys_id']}")
    log(:info, "state: #{opsmgr_result['state']}")

    log(:info, "Adding custom attribute {:opsmgr_incident_number => #{opsmgr_result['number']}}")
    @object.custom_set(:opsmgr_incident_number, opsmgr_result['number'].to_s)
    log(:info, "Adding custom attribute {:opsmgr_incident_sysid => #{opsmgr_result['sys_id']}}")
    @object.custom_set(:opsmgr_incident_sysid, opsmgr_result['sys_id'].to_s)
    log(:info, "Resetting custom attribute {:opsmgr_incident_state => #{opsmgr_result['state']}}")
    @object.custom_set(:opsmgr_incident_state, opsmgr_result['state'].to_s)
  end

rescue => err
  log(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_STOP
end
