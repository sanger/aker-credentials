require 'jwt'
require 'ostruct'
require 'request_store'
require 'jwt_serializer'
require 'faraday'
require 'active_support'
require 'active_support/core_ext'

module JWTCredentials
  def self.included(base)
    base.instance_eval do |klass|
      before_action :check_credentials
      before_action :apply_credentials

      def self.skip_credentials?(action)
        return false unless @skip_credentials
        return true unless @skip_credentials_options
        if @skip_credentials_options[:only]
          return @skip_credentials_options[:only].include?(action)
        end
        if @skip_credentials_options[:except]
          return !@skip_credentials_options[:except].include?(action)
        end
        return true
      end

      def self.skip_credentials(options = nil)
        @skip_credentials = true
        @skip_credentials_options = options
      end
    end
  end

  attr_reader :x_auth_user

  def current_user
    if respond_to?(:auth_user)
      auth_user || x_auth_user
    else
      x_auth_user
    end
  end

  def apply_credentials
    RequestStore.store[:x_authorisation] = current_user
  end

  def build_user(hash)
    @x_auth_user = if defined? User
                     User.from_jwt_data(hash)
                   else
                     OpenStruct.new(hash)
                   end
  end

  def check_credentials
    @x_auth_user = nil
    return if self.class.skip_credentials?(self.action_name.to_sym)
    if request.headers.to_h['HTTP_X_AUTHORISATION']
      # JWT present in header (microservices)
      begin
        user_from_jwt(request.headers.to_h['HTTP_X_AUTHORISATION'])
      rescue JWT::VerificationError => e
        head :unauthorized
      rescue JWT::ExpiredSignature => e
        head :unauthorized
      end
    elsif cookies[:aker_user_jwt]
      # JWT present in cookie (front-end apps)
      Rails.logger.info("JWT in cookie: #{cookies[:aker_user_jwt]}")
      begin
        user_from_jwt(cookies[:aker_user_jwt])
      rescue JWT::VerificationError => e
        # Potential hacking attempt so log this
        jwt = JWT.decode cookies[:aker_user_jwt], '', false, algorithm: 'HS256'
        Rails.logger.warn("JWT verification failed from #{request.ip}, JWT: #{jwt}")
        # Then delete their cookies
        cookies.delete :aker_auth_session
        cookies.delete :aker_user_jwt
        redirect_to login_url
      rescue JWT::ExpiredSignature => e
        Rails.logger.info("EXPIRED JWT in cookie: #{cookies[:aker_user_jwt]}")
        request_jwt
      end
    elsif default_user
      # Fake JWT User for development
      build_user(default_user)
    elsif cookies[:aker_auth_session]
      request_jwt
    else
      redirect_to login_url
    end
  end

  def jwt_provided?
    x_auth_user.present?
  end

  def user_from_jwt(jwt_container)
    payload, _header = JWT.decode jwt_container, secret_key, true, algorithm: 'HS256'
    build_user(payload['data'])
  end

  def request_jwt
    begin
      Rails.logger.info("About to attmpt to renew JWT")
      success = renew_jwt(cookies[:aker_auth_session])
    rescue
      success = false
    end
    unless success
      Rails.logger.info("Request failed, redirect to login page")
      redirect_to login_url
    end
  end

  # This method may return nil or throw an exception if some part of it fails
  def renew_jwt(auth_session)
    Rails.logger.info("Auth session ID: #{auth_session}")
    return nil unless auth_session
    conn = Faraday.new(url: renew_url)
    auth_response = conn.post do |req|
      req.headers['Cookie'] = "aker_auth_session=#{auth_session}"
    end # may throw an exception for some response statuses
    Rails.logger.info("Auth service response to renewal attempt: #{auth_response}")
    return nil unless auth_response.status == 200
    user_from_jwt(auth_response.body) # may throw an exception if jwt is invalid or expired
    # send the new cookie back to the user
    response.headers['set-cookie'] = auth_response.headers['set-cookie']
    auth_response.body
  end

  def login_url
    params = {
      redirect_url: request.original_url
    }
    Rails.configuration.login_url + '?' + params.to_query
  end

  def default_user
    if Rails.configuration.respond_to? :default_jwt_user
      Rails.configuration.default_jwt_user
    else
      nil
    end
  end

  def secret_key
    Rails.configuration.jwt_secret_key
  end

  def renew_url
    Rails.configuration.auth_service_url + '/renew_jwt'
  end
end
