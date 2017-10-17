require 'spec_helper'
require 'faraday'
require 'active_support'
require 'active_support/core_ext'

RSpec.describe JWTCredentials do
  let(:rails) { double('Rails', logger: logger, configuration: config) }
  let(:logger) do
    log = double('Logger')
    allow(log).to receive(:warn)
    log
  end

  let(:config) { double('config', login_url: 'http://loginurl', auth_service_url: 'http://authserviceurl', jwt_secret_key: jwt_key) }
  let(:request) { double('request', headers: {}, ip: '1', original_url: 'http://originalurl') }
  let(:login_url_with_parameters) { config.login_url+'?'+{redirect_url: request.original_url}.to_query }
  let(:jwt_key) { 'top_secret' }
  let(:userhash) { {"email"=>"test@sanger.ac.uk", "groups"=>["world"] } }

  def make_jwt(time_offset, key)
    iat = Time.now.to_i + time_offset
    nbf = iat - 5
    exp = iat + 5
    payload = {
      data: userhash, iat: iat, exp: exp, nbf: nbf
    }
    JWT.encode payload, key, 'HS256'
  end

  let(:valid_jwt) { make_jwt(0, jwt_key) }
  let(:expired_jwt) { make_jwt(-30, jwt_key) }
  let(:invalid_jwt) { make_jwt(0, 'wrong_key') }

  let(:cookies) { {} }

  class CredentialsClass
    def self.before_action(symbol)
    end
    attr_accessor :action_name
    def action_name
      @action_name || 'some_action'
    end
    include JWTCredentials
  end

  let(:credentials_instance) { CredentialsClass.new }

  before do
    allow(credentials_instance).to receive(:cookies).and_return(cookies)
    allow(credentials_instance).to receive(:request).and_return(request)
    allow(credentials_instance).to receive(:redirect_to)
    stub_const('Rails', rails)
  end

  describe(:check_credentials) do
    context 'when the JWT is valid' do
      let(:cookies) { { aker_user_jwt: valid_jwt } }
      it 'extracts the user' do
        credentials_instance.check_credentials
        x = credentials_instance.x_auth_user
        expect(x).not_to be_nil
        expect(x.email).to eq(userhash["email"])
      end
      it 'does not redirect' do
        expect(credentials_instance).not_to have_received(:redirect_to)
      end

    end

    context 'when the JWT has expired' do
      let(:cookies) { { aker_user_jwt: expired_jwt } }
      before do
        allow(credentials_instance).to receive(:request_jwt)
        credentials_instance.check_credentials
      end
      it 'does not store the user' do
        expect(credentials_instance.x_auth_user).to be_nil
      end
      it 'calls request_jwt' do
        expect(credentials_instance).to have_received(:request_jwt)
      end
      it 'does not redirect' do
        expect(credentials_instance).not_to have_received(:redirect_to)
      end
    end

    context 'when the JWT is invalid' do
      let(:cookies) { { aker_user_jwt: invalid_jwt } }

      before do
        allow(cookies).to receive(:delete)
        credentials_instance.check_credentials
      end
      it 'logs a warning' do
        expect(logger).to have_received(:warn)
      end
      it 'redirects to the login page' do
        expect(credentials_instance).to have_received(:redirect_to).with(login_url_with_parameters)
      end
      it 'deletes the cookies' do
        expect(cookies).to have_received(:delete).with(:aker_auth_session)
        expect(cookies).to have_received(:delete).with(:aker_user_jwt)
      end
      it 'does not store the user' do
        expect(credentials_instance.x_auth_user).to be_nil
      end
    end

    context 'when the user has an auth session but no JWT' do
      let(:cookies) { { aker_auth_session: 'some_session_id' } }

      before do
        allow(credentials_instance).to receive(:request_jwt)
        credentials_instance.check_credentials
      end
      it 'does not store the user' do
        expect(credentials_instance.x_auth_user).to be_nil
      end
      it 'calls request_jwt' do
        expect(credentials_instance).to have_received(:request_jwt)
      end
      it 'does not redirect' do
        expect(credentials_instance).not_to have_received(:redirect_to)
      end
    end

    context 'when there is no auth session and no JWT' do
      before do
        allow(credentials_instance).to receive(:request_jwt)
        credentials_instance.check_credentials
      end
      it 'redirects to the login page' do
        expect(credentials_instance).to have_received(:redirect_to).with(login_url_with_parameters)
      end
    end

    context 'when credentials are skipped' do
      context 'when they are fully skipped' do
        before do
          CredentialsClass.skip_credentials
        end
        it 'does not redirect' do
          credentials_instance.check_credentials
          expect(credentials_instance).not_to have_received(:redirect_to)
        end
      end
      context 'when they are skipped only for certain actions' do
        before do
          CredentialsClass.skip_credentials(only: [:alpha])
        end
        it 'does not redirect the listed action' do
          credentials_instance.action_name = 'alpha'
          credentials_instance.check_credentials
          expect(credentials_instance).not_to have_received(:redirect_to)
        end
        it 'redirects unlisted actions' do
          credentials_instance.action_name = 'beta'
          credentials_instance.check_credentials
          expect(credentials_instance).to have_received(:redirect_to)
        end
      end
      context 'when they are skipped except for certain actions' do
        before do
          CredentialsClass.skip_credentials(except: [:alpha])
        end
        it 'does not redirect unlisted actions' do
          credentials_instance.action_name = 'beta'
          credentials_instance.check_credentials
          expect(credentials_instance).not_to have_received(:redirect_to)
        end
        it 'redirects listed actions' do
          credentials_instance.action_name = 'alpha'
          credentials_instance.check_credentials
          expect(credentials_instance).to have_received(:redirect_to)
        end
      end
    end

  end

  describe(:request_jwt) do
    let(:conn) { double("Faraday") }
    let(:cookie_data) { '[cookie data]'}
    let(:auth_status) { 200 }
    let(:auth_response) { double('auth response', status: auth_status, body: valid_jwt, headers: { 'set-cookie' => cookie_data}) }
    let(:response) { double('response', headers: headers)}
    let(:headers) { {} }
    let(:auth_error) { nil }
    before do
      allow(credentials_instance).to receive(:redirect_to)
      allow(credentials_instance).to receive(:response).and_return(response)
      allow(Faraday).to receive(:new).and_return(conn)
      if auth_error
        allow(conn).to receive(:post).and_raise(auth_error)
      else
        allow(conn).to receive(:post).and_return(auth_response)
      end
      credentials_instance.request_jwt
    end

    context 'when the user has an auth session cookie' do
      let(:cookies) { { aker_auth_session: 'auth_session' } }

      context 'when the request succeeds' do
        it 'sends back a cookie' do
          expect(headers['set-cookie']).to eq(cookie_data)
        end

        it 'processes the jwt' do
          expect(credentials_instance.x_auth_user).not_to be_nil
          expect(credentials_instance.x_auth_user.email).to eq(userhash['email'])
        end
      end

      context 'when the request fails' do
        let(:auth_status) { 401 }

        it 'does not send back a cookie' do
          expect(headers['set-cookie']).to be_nil
        end

        it 'redirects to the login page' do
          expect(credentials_instance).to have_received(:redirect_to).with(login_url_with_parameters)
        end
      end

      context 'when the request raises' do
        let(:auth_error) { 'Error' }

        it 'does not send back a cookie' do
          expect(headers['set-cookie']).to be_nil
        end

        it 'redirects to the login page' do
          expect(credentials_instance).to have_received(:redirect_to).with(login_url_with_parameters)
        end
      end
    end
    context 'when the user has no auth session cookie' do
      it 'does not send back a cookie' do
        expect(headers['set-cookie']).to be_nil
      end

      it 'redirects to the login page' do
        expect(credentials_instance).to have_received(:redirect_to).with(login_url_with_parameters)
      end
    end
  end
end
