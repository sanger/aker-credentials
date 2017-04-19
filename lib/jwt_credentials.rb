require 'jwt'
require 'ostruct'
require 'request_store'

module JWTCredentials

  def self.included(base)
    base.instance_eval do |klass|
      #include JWTCredentials:Checks
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
    #debugger    
    if defined? User
      session['user'] = User.from_jwt_data(hash)
      #session['user'] = User.new(hash)
    else
      session['user'] = OpenStruct.new(hash)
    end    
  end

  def check_credentials
    #debugger
    if request.headers.to_h['HTTP_X_AUTHORISATION']
      begin
        secret_key = Rails.configuration.jwt_secret_key
        token = request.headers.to_h['HTTP_X_AUTHORISATION']
        payload, header = JWT.decode token, secret_key, true, { algorithm: 'HS256'}
        ud = payload["data"]
        build_user_session(ud)
        #if defined? User
        #  session['user'] = User.new(ud['user'])
        #else
        #  session['user'] = OpenStruct.new(ud['user'])
        #end
        #session["user"] = {
        #  "user" => ud["user"], #User.find_or_create_by(email: ud["user"]["email"]),
        #  "groups" => ["world"]#ud["groups"].join(',') #ud["groups"].map { |name| Group.find_or_create_by(name: name) },
        #}

      rescue JWT::VerificationError => e
        render body: nil, status: :unauthorized
      rescue JWT::ExpiredSignature => e
        render body: nil, status: :unauthorized
      end
    else
      if current_user
        session['user']=current_user
      else
        build_user_session("email" => 'guest', "groups" => ['world'])
      end
    end
  end  
end
