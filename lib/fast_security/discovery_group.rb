# coding: utf-8
require 'jwt'

module FASTSecurity
  class DiscoveryGroup < Inferno::TestGroup
    include Inferno::DSL::Assertions

    title 'FAST Discovery'
    description %(
      Verify that server configuration is made available and conforms with [the
      discovery
      requirements](https://hl7.org/fhir/us/udap-security/discovery.html).
    )
    id :discovery_group

    run_as_group

    def assert_array_of_strings(config, field)
      values = config[field]
      assert values.is_a?(Array),
             "`#{field}` should be an Array, but found #{values.class.name}"
      non_string_values = values.select { |value| !value.is_a?(String) }
      assert non_string_values.blank?,
             "`#{field}` should be an Array of strings, " \
             "but found #{non_string_values.map(&:class).map(&:name).join(', ')}"
    end

    test do
      title 'UDAP Well-Known configuration is available'
      description %(
        The metadata returned from `{baseURL}/.well-known/udap` **SHALL**
        represent the server’s capabilities with respect to the UDAP workflows
        described in this guide.
      )

      input :url
      output :config_json
      makes_request :config

      run do
        get("#{url.strip.chomp('/')}/.well-known/udap", name: :config)
        assert_response_status(200)
        assert_valid_json(response[:body])
        output config_json: response[:body]
      end
    end

    test do
      title 'udap_versions_supported field'
      description %(
        `udap_versions_supported` must contain a fixed array with one string
        element: `["1"]`
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)
        assert config['udap_versions_supported'] == ['1'],
               "`udap_versions_supported` field must contain an array with one string element '1'"
      end
    end

    test do
      title 'udap_certifications_supported field'
      description %(
        `udap_certifications_supported` is an array of zero or more
        certification URIs
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('udap_certifications_supported'), "`udap_certifications_supported` is a required field"

        assert_array_of_strings(config, 'udap_certifications_supported')

        non_uri_values =
          config['udap_certifications_supported']
            .select { |value| !value.match?(URI.regexp) }

        assert non_uri_values.blank?,
               '`udap_certifacations_supported` should be an Array of URI strings, ' \
               "but found #{non_uri_values.map(&:class).map(&:name).join(', ')}"
      end
    end

    test do
      title 'udap_certifications_required field'
      description %(
        If `udap_certifications_supported` is not empty, then `udap_certifications_required` is an array of zero or more
        certification URIs
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        skip_if !config.key?('udap_certifications_supported'), 'Assessment of `udap_certifications_required` field is dependent on values in `udap_certifications_supported` field, which is not present'

        omit_if config['udap_certifications_supported'].blank?, 'No UDAP certifications are supported'

        assert_array_of_strings(config, 'udap_certifications_required')

        non_uri_values =
          config['udap_certifications_required']
            .select { |value| !value.match?(URI.regexp) }

        assert non_uri_values.blank?,
               '`udap_certifacations_required` should be an Array of URI strings, ' \
               "but found #{non_uri_values.map(&:class).map(&:name).join(', ')}"
      end
    end

    test do
      title 'grant_types_supported field'
      description %(
        `grant_types_supported` is an array of one or more grant types
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('grant_types_supported'), "`grant_types_supported` is a required field"

        assert_array_of_strings(config, 'grant_types_supported')

        grant_types = config['grant_types_supported']

        assert grant_types.length() >= 1, "Must include at least 1 supported grant type"

        if grant_types.include?('refresh_token')
          assert grant_types.include?('authorization_code'),
                 'The `refresh_token` grant type **SHALL** only be included if the ' \
                 '`authorization_code` grant type is also included.'
        end
      end
    end

    test do
      title 'scopes_supported field'
      description %(
        If present, `scopes_supported` is an array of one or more
        strings containing scopes
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('scopes_supported')

        assert_array_of_strings(config, 'scopes_supported')
      end
    end

    test do
      title 'authorization_endpoint field'
      description %(
        `authorization_endpoint` is a string containing the absolute URL of the Authorization Server's authorization endpoint. This parameter SHALL be present if the value of the grant_types_supported parameter includes the string "authorization_code"
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        skip_if (!config.key?('grant_types_supported') || !config['grant_types_supported'].is_a?(Array)), 'Assessment of `authorization_endpoint` field is dependent on values in `grant_types_supported` field, which is not present or correctly formatted'

        omit_if !config['grant_types_supported'].include?('authorization_code'), '`authorization_endpoint` field is only required if `authorization_code` is a supported grant type'

        assert config.key?('authorization_endpoint'), '`authorization_endpoint` field is required if `authorization_endpoint` is a supported grant type'

        endpoint = config['authorization_endpoint']

        assert endpoint.is_a?(String),
               "`authorization_endpoint` should be a String, but found #{endpoint.class.name}"
        assert endpoint.match?(URI.regexp), "`#{endpoint}` is not a valid URI"
      end
    end

    test do
      title 'token_endpoint field'
      description %(
       `token_endpoint` is a string containing the URL of
        the Authorization Server's token endpoint
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('token_endpoint'), '`token_endpoint` is a required field'

        endpoint = config['token_endpoint']

        assert endpoint.is_a?(String),
               "`token_endpoint` should be a String, but found #{endpoint.class.name}"
        assert endpoint.match?(URI.regexp), "`#{endpoint}` is not a valid URI"
      end
    end

    test do
      title 'token_endpoint_auth_methods_supported field'
      description %(
        `token_endpoint_auth_methods_supported` must contain a fixed
        array with one string element: `["private_key_jwt"]`
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config['token_endpoint_auth_methods_supported'] == ['private_key_jwt'],
               "`token_endpoint_auth_methods_supported` field must contain an array " \
               "with one string element 'private_key_jwt'"
      end
    end

    test do
      title 'token_endpoint_auth_signing_alg_values_supported field'
      description %(
       `token_endpoint_auth_signing_alg_values_supported` is an
        array of one or more strings identifying signature algorithms supported by the Authorization Server for validation of signed JWTs submitted to the token endpoint for client authentication.
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('token_endpoint_auth_signing_alg_values_supported'), '`token_endpoint_auth_signing_alg_values_supported` is a required field'

        assert_array_of_strings(config, 'token_endpoint_auth_signing_alg_values_supported')

        algs_supported = config['token_endpoint_auth_signing_alg_values_supported']

        assert algs_supported.length() >= 1, 'Must support at least one signature algorithm'
      end
    end

    test do
      title 'registration_endpoint field'
      description %(
        `registration_endpoint` is a string containing the URL of
        the Authorization Server's registration endpoint
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('registration_endpoint'), '`registration_endpoint` is a required field'

        endpoint = config['registration_endpoint']

        assert endpoint.is_a?(String),
               "`registration_endpoint` should be a String, but found #{endpoint.class.name}"
        assert endpoint.match?(URI.regexp), "`#{endpoint}` is not a valid URI"
      end
    end

    test do
      title 'registration_endpoint_jwt_signing_alg_values_supported field'
      description %(
        If present, `registration_endpoint_jwt_signing_alg_values_supported` is
        an array of one or more strings identifying signature algorithms supported by the Authorization Server for validation of signed software statements, certifications, and endorsements submitted to the registration endpoint.
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('registration_endpoint_jwt_signing_alg_values_supported'), '`registration_endpoint_jwt_signing_alg_values_supported` field is recommended but not required'

        assert_array_of_strings(config, 'registration_endpoint_jwt_signing_alg_values_supported')
      end
    end

    test do
      title 'signed_metadata field'
      description %(
       `signed_metadata` is a string containing a JWT listing the server's endpoints
      )

      input :config_json
      output :signed_metadata_jwt

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('signed_metadata'), '`signed_metadata is a required field'
        jwt = config['signed_metadata']

        assert jwt.is_a?(String), "`signed_metadata` should be a String, but found #{jwt.class.name}"
        output signed_metadata_jwt: jwt

        jwt_regex = %r{^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$}

        assert jwt.match?(jwt_regex), '`signed_metadata` is not a valid JWT'
      end
    end

    test do
      title 'signed_metadata contents'
      description %(
        Validate the contents of the `signed_metadata` header, signature, and
        contents.
      )

      input :signed_metadata_jwt, optional: true
      input :config_json, :url

      run do
        omit_if signed_metadata_jwt.blank?

        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        token_body, token_header = JWT.decode(signed_metadata_jwt, nil, false)

        assert token_header.key?('x5c'), 'JWT header does not contain `x5c` field'
        assert token_header.key?('alg'), 'JWT header does not contain `alg` field'

        cert = OpenSSL::X509::Certificate.new(Base64.decode64(token_header['x5c'].first))
        # TODO: handle root certs and crls
        JWT.decode(
          signed_metadata_jwt,
          cert.public_key,
          true,
          algorithm: token_header['alg']
        )

        ['iss', 'sub', 'exp', 'iat', 'jti'].each do |key|
          assert token_body.key?(key), "JWT does not contain `#{key}` claim"
        end

        ['authorization_endpoint', 'token_endpoint', 'registration_endpoint']
          .select { |key| config.key? key }
          .each do |key|
            assert token_body.key?(key), "JWT must contain `#{key}` claim if it is included in the unsigned metadata"
          end

        assert token_body['iss'] == url, "`iss` claim `#{token_body['iss']}` is not the same as server base url `#{url}`"
        alt_name =
          cert.extensions
            .find { |extension| extension.oid == 'subjectAltName' }
            .value
            .delete_prefix('URI:')
        assert token_body['iss'] == alt_name,
               "`iss` claim `#{token_body['iss']}` does not match Subject Alternative Name extension " \
               "from the `x5c` JWT header `#{alt_name}`"
        assert token_body['iss'] == token_body['sub'],
               "`iss` claim `#{token_body['iss']}` does not match `sub` claim `#{token_body['sub']}`"

        ['iat', 'exp'].each do |key|
          assert token_body[key].is_a?(Numeric), "Expected `#{key}` to be numeric, but found #{token_body[key].class.name}"
        end
        issue_time = Time.at(token_body['iat'])
        expiration_time = Time.at(token_body['exp'])

        assert expiration_time <= issue_time + 1.year, %(
          `exp` is more than a year after `iat`'.
          * `iat`: #{token_body['iat']} - #{issue_time.iso8601}
          * `exp`: #{token_body['exp']} - #{expiration_time.iso8601}
        )
      end
    end
  
    test do 
      title 'udap_profiles_supported field'
      description %(
        `udap_profiles_supported` is an array of two or more strings identifying the core UDAP profiles supported by the Authorization Server. The array SHALL include:
        `udap_dcr` for UDAP Dynamic Client Registration, and
        `udap_authn` for UDAP JWT-Based Client Authentication.
        If the `grant_types_supported` parameter includes the string `client_credentials`, then the array SHALL also include:
        `udap_authz` for UDAP Client Authorization Grants using JSON Web Tokens to indicate support for Authorization Extension Objects.
      )

      input :config_json

      run do 
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('udap_profiles_supported'), '`udap_profiles_supported` is a required field'

        assert_array_of_strings(config, 'udap_profiles_supported')

        profiles_supported = config['udap_profiles_supported']
        
        assert profiles_supported.include?('udap_dcr'), 'Array must include `udap_dcr` to indicate support for required UDAP Dynamic Client Registration profile'

        assert profiles_supported.include?('udap_authn'), 'Array must include `udap_authn` value to indicate support for required UDAP JWT-Based Client Authentication profile'

        if (config.key?('grant_types_supported') && config['grant_types_supported'].include?('client_credentials'))
          assert profiles_supported.include?('udap_authz'), '`client_credentials` grant type is supported, so array must include `udap_authz` to indicate support for UDAP Client Authorization Grants using JSON Web Tokens'
        end
      end
    end

    test do
      title 'udap_authorization_extensions_supported field'
      description %(
        `udap_authorization_extensions_supported` is an array of zero or more recognized key names for Authorization Extension Objects supported by the Authorization Server.
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        assert config.key?('udap_authorization_extensions_supported'), '`udap_authorization_extensions_supported` is a required field'

        assert config['udap_authorization_extensions_supported'].is_a?(Array), "`udap_authorization_extensions_supported` must be an array"
      end
    end

    test do 
      title 'udap_authorization_extensions_required field'
      description %(
        `udap_authorization_extensions_required field` is an array of zero or more recognized key names for Authorization Extension Objects required by the Authorization Server in every token request. This metadata parameter SHALL be present if the value of the `udap_authorization_extensions_supported` parameter is not an empty array.
      )

      input :config_json

      run do 
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        skip_if !config.key?('udap_authorization_extensions_supported') || !config['udap_authorization_extensions_supported'].is_a?(Array), 'Assessment of `authorization_endpoint` field is dependent on values in `grant_types_supported` field, which is not present or correctly formatted'

        omit_if config['udap_authorization_extensions_supported'].blank?, 'No UDAP authorization extensions are supported'

        assert config.key?('udap_authorization_extensions_required'), '`udap_authorization_extensions_required` field must be present because `udap_authorization_extensions_supported field is not empty'

        assert config['udap_authorization_extensions_required'].is_a?(Array), '`udap_authorization_extensions_required` must be an array'
      end
    end
  end
end
