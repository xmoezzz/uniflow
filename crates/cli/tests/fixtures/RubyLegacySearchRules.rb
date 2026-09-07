require 'jwt'
Rails.application.config.action_dispatch.cookies_serializer = :marshal
syscall(1)
config.serve_static_assets = true
config.force_ssl = false
ActiveSupport.escape_html_entities_in_json = false
attr_protected :secret
accepts_nested_attributes_for :items, allow_destroy: false
OpenSSL::SSL::VERIFY_NONE
http_basic_authenticate_with name: user
ActionController::Base.param_parsers[Mime::YAML] = :yaml
skip_forgery_protection
content_tag(:div, value)
value.html_safe
raw(value)
render inline: template
render text: value
ERB.new(template)
ActiveSupport::XmlMini.backend = "LibXML"
Digest::MD5.hexdigest(value)
OpenSSL::HMAC.digest("sha1", key, value)

def audit(command, dynamic_backend, params)
  open(command)
  Open3.pipeline(command)
  accepts_nested_attributes_for :children
  XmlMini.backend = dynamic_backend
  params.permit(:admin)
  params.permit(:role)
  JWT.decode(params, dynamic_backend, false)
  JWT.encode(params, dynamic_backend, 'none')
  secret = 'hardcoded'
  JWT.encode(params, secret, 'HS256')
end
