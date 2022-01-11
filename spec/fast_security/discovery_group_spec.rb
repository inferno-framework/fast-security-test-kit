RSpec.describe FASTSecurity::DiscoveryGroup do
  let(:suite) { Inferno::Repositories::TestSuites.new.find('fast_security') }
  let(:group) { suite.groups[0] }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'fast_security') }
  let(:url) { 'http://example.com/fhir' }
  let(:valid_capabilities) do
    FHIR::CapabilityStatement.new(
      fhirVersion: '4.0.1',
      rest: [
        {
          security: {
            service: [
              {
                coding: {
                  code: 'http://fhir.udap.org/CodeSystem/capability-rest-security-service|UDAP'
                }
              }
            ]
          }
        }
      ]
    )
  end

  def run(runnable, inputs = {})
    test_run_params = { test_session_id: test_session.id }.merge(runnable.reference_hash)
    test_run = Inferno::Repositories::TestRuns.new.create(test_run_params)
    inputs.each do |name, value|
      session_data_repo.save(test_session_id: test_session.id, name: name, value: value)
    end
    Inferno::TestRunner.new(test_session: test_session, test_run: test_run).run(runnable)
  end

  describe 'Capability Statement test' do
    let(:test) { group.tests.first }

    it 'passes if a CS lists UDAP support' do
      stub_request(:get, "#{url}/metadata")
        .to_return(status: 200, body: valid_capabilities.to_json)

      result = run(test, url: url)

      expect(result.result).to eq('pass')
    end

    it 'fails if a 200 is not received' do
      stub_request(:get, "#{url}/metadata")
        .to_return(status: 201, body: valid_capabilities.to_json)

      result = run(test, url: url)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/200/)
    end

    it 'fails if it receives invalid JSON' do
      stub_request(:get, "#{url}/metadata")
        .to_return(status: 200, body: '[[')

      result = run(test, url: url)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Invalid JSON/)
    end

    it 'fails if the CS does not list UDAP support' do
      resource = FHIR::CapabilityStatement.new(fhirVersion: '4.0.1')
      stub_request(:get, "#{url}/metadata")
        .to_return(status: 200, body: resource.to_json)

      result = run(test, url: url)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/UDAP service not included/)
    end
  end

  describe 'Well-Known configuration test' do
    let(:test) { group.tests[1] }

    it 'passes if JSON is served from the UDAP well-known endpoint' do
      stub_request(:get, "#{url}/.well-known/udap")
        .to_return(status: 200, body: {}.to_json)

      result = run(test, url: url)

      expect(result.result).to eq('pass')
    end

    it 'fails if a 200 is not received' do
      stub_request(:get, "#{url}/.well-known/udap")
        .to_return(status: 201, body: {}.to_json)

      result = run(test, url: url)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/200/)
    end

    it 'fails if it receives invalid JSON' do
      stub_request(:get, "#{url}/.well-known/udap")
        .to_return(status: 200, body: '[[')

      result = run(test, url: url)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Invalid JSON/)
    end
  end

  describe 'udap_versions_supported field test' do
    let(:test) { group.tests[2] }

    it 'fails if field is not ["1"]' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match('must contain an array')
    end

    it 'passes if udap_versions_supported is ["1"]' do
      config = { udap_versions_supported: ['1'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end
  end

  describe 'udap_certifications_supported field test' do
    let(:test) { group.tests[3] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if udap_certifications_supported is an array of uri strings' do
      config = { udap_certifications_supported: ['http://abc', 'http://def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if udap_certifications_supported is not an array' do
      config = { udap_certifications_supported: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if udap_certifications_supported is an array with a non-string element' do
      config = { udap_certifications_supported: ['http://abc', 1] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end

    it 'fails if udap_certifications_supported is an array with a non-uri string element' do
      config = { udap_certifications_supported: ['http://abc', 'def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of URI strings/)
    end
  end

  describe 'udap_certifications_required field test' do
    let(:test) { group.tests[4] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if udap_certifications_required is an array of uri strings' do
      config = { udap_certifications_required: ['http://abc', 'http://def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if udap_certifications_required is not an array' do
      config = { udap_certifications_required: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if udap_certifications_required is an array with a non-string element' do
      config = { udap_certifications_required: ['http://abc', 1] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end

    it 'fails if udap_certifications_required is an array with a non-uri string element' do
      config = { udap_certifications_required: ['http://abc', 'def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of URI strings/)
    end
  end

  describe 'grant_types_supported field test' do
    let(:test) { group.tests[5] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if grant_types_supported is an array of uri strings' do
      config = { grant_types_supported: ['http://abc', 'http://def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if grant_types_supported is not an array' do
      config = { grant_types_supported: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if grant_types_supported is an array with a non-string element' do
      config = { grant_types_supported: ['http://abc', 1] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end

    it 'fails if grant_types_supported includes refresh_token without authorization_code' do
      config = { grant_types_supported: ['refresh_token'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/authorization_code/)
    end
  end

  describe 'scopes_supported field test' do
    let(:test) { group.tests[6] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if scopes_supported is an array of uri strings' do
      config = { scopes_supported: ['http://abc', 'http://def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if scopes_supported is not an array' do
      config = { scopes_supported: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if scopes_supported is an array with a non-string element' do
      config = { scopes_supported: ['http://abc', 1] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end
  end

  describe 'authorization_endpoint field test' do
    let(:test) { group.tests[7] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if authorization_endpoint is a uri strings' do
      config = { authorization_endpoint: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if authorization_endpoint is not a string' do
      config = { authorization_endpoint: ['http://abc'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be a String/)
    end

    it 'fails if authorization_endpoint is a non-uri string' do
      config = { authorization_endpoint: 'def' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/valid URI/)
    end
  end

  describe 'token_endpoint field test' do
    let(:test) { group.tests[8] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if token_endpoint is a uri strings' do
      config = { token_endpoint: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if token_endpoint is not a string' do
      config = { token_endpoint: ['http://abc'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be a String/)
    end

    it 'fails if token_endpoint is a non-uri string' do
      config = { token_endpoint: 'def' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/valid URI/)
    end
  end

  describe 'token_endpoint_auth_methods_supported field test' do
    let(:test) { group.tests[9] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if token_endpoint_auth_methods_supported is ["private_key_jwt"]' do
      config = { token_endpoint_auth_methods_supported: ['private_key_jwt'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if token_endpoint_auth_methods_supported is not ["private_key_jwt"]' do
      config = { token_endpoint_auth_methods_supported: 'abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/must contain an array with/)
    end
  end

  describe 'token_endpoint_auth_signing_alg_values_supported field test' do
    let(:test) { group.tests[10] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if token_endpoint_auth_signing_alg_values_supported is an array of uri strings' do
      config = { token_endpoint_auth_signing_alg_values_supported: ['http://abc', 'http://def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if token_endpoint_auth_signing_alg_values_supported is not an array' do
      config = { token_endpoint_auth_signing_alg_values_supported: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if token_endpoint_auth_signing_alg_values_supported is an array with a non-string element' do
      config = { token_endpoint_auth_signing_alg_values_supported: ['http://abc', 1] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end
  end

  describe 'registration_endpoint field test' do
    let(:test) { group.tests[11] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if registration_endpoint is a uri strings' do
      config = { registration_endpoint: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if registration_endpoint is not a string' do
      config = { registration_endpoint: ['http://abc'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be a String/)
    end

    it 'fails if registration_endpoint is a non-uri string' do
      config = { registration_endpoint: 'def' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/valid URI/)
    end
  end

  describe 'registration_endpoint_jwt_signing_alg_values_supported field test' do
    let(:test) { group.tests[12] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'passes if registration_endpoint_jwt_signing_alg_values_supported is an array of uri strings' do
      config = { registration_endpoint_jwt_signing_alg_values_supported: ['http://abc', 'http://def'] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'fails if registration_endpoint_jwt_signing_alg_values_supported is not an array' do
      config = { registration_endpoint_jwt_signing_alg_values_supported: 'http://abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be an Array/)
    end

    it 'fails if registration_endpoint_jwt_signing_alg_values_supported is an array with a non-string element' do
      config = { registration_endpoint_jwt_signing_alg_values_supported: ['http://abc', 1] }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/Array of strings/)
    end
  end

  describe 'signed_metadata field test' do
    let(:test) { group.tests[13] }

    it 'omits if field is not present' do
      config = {}

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('omit')
    end

    it 'fails if signed_metadata is not a String' do
      config = { signed_metadata: 1 }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/be a String/)
    end

    it 'fails if signed_metadata is not a JWT' do
      config = { signed_metadata: 'abc' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('fail')
      expect(result.result_message).to match(/not a valid JWT/)
    end

    it 'passes if signed_metadata is a JWT' do
      config = { signed_metadata: 'abc.def.xyz' }

      result = run(test, config_json: config.to_json)

      expect(result.result).to eq('pass')
    end
  end
end
