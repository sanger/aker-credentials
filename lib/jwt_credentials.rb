require 'jwt'
require 'ostruct'
require 'request_store'

module JWTCredentials

  # When our user data gets serialized inside a session, we don't want the
  # fields nested against a "table" key
  class JWTOpenStruct < OpenStruct
    def as_json(options = nil)
      @table.as_json(options)
    end
  end

  def self.included(base)
    base.instance_eval do |klass|
      before_action :check_credentials
      before_action :apply_credentials
    end
  end

  def apply_credentials
    if current_user
      session['user'] = current_user
    end
    RequestStore.store[:x_authorisation] = session['user']
  end

  def build_user_session(hash)
    if defined? User
      session['user'] = User.from_jwt_data(hash)
    else
      session['user'] = JWTOpenStruct.new(hash)
    end    
  end

  def check_credentials
    # Don't let session['user'] from previous operations be perpetuated
    session['user'] = nil
    if request.headers.to_h['HTTP_X_AUTHORISATION']
      begin
        secret_key = Rails.configuration.jwt_secret_key
        token = request.headers.to_h['HTTP_X_AUTHORISATION']
        payload, header = JWT.decode token, secret_key, true, { algorithm: 'HS256'}
        ud = payload["data"]
        build_user_session(ud)
      rescue JWT::VerificationError => e
        render body: nil, status: :unauthorized
      rescue JWT::ExpiredSignature => e
        render body: nil, status: :unauthorized
      end
    else
      if current_user
        session['user'] = current_user
      else
        build_user_session("email" => 'guest', "groups" => ['world'])
      end
    end
  end  
end
