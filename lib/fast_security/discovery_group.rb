# coding: utf-8
require 'jwt'

module FASTSecurity
  class DiscoveryGroup < Inferno::TestGroup
    include Inferno::DSL::Assertions
    title 'FAST Discovery'
    description 'Verify that server configuration is made available'
    id :discovery_group

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
        If present, `udap_certifications_supported` is an array of zero or more
        certification URIs
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('udap_certifications_supported')

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
        If present, `udap_certifications_required` is an array of zero or more
        certification URIs
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('udap_certifications_required')

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
        If present, `grant_types_supported` is an array of one or more
        grant types
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('grant_types_supported')

        assert_array_of_strings(config, 'grant_types_supported')

        grant_types = config['grant_types_supported']

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
        If present, `authorization_endpoint` is a string containing the URL of
        the Authorization Server's authorization endpoint
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('authorization_endpoint')

        endpoint = config['authorization_endpoint']

        assert endpoint.is_a?(String),
               "`authorization_endpoint` should be a String, but found #{endpoint.class.name}"
        assert endpoint.match?(URI.regexp), "`#{endpoint}` is not a valid URI"
      end
    end

    test do
      title 'token_endpoint field'
      description %(
        If present, `token_endpoint` is a string containing the URL of
        the Authorization Server's token endpoint
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('token_endpoint')

        endpoint = config['token_endpoint']

        assert endpoint.is_a?(String),
               "`token_endpoint` should be a String, but found #{endpoint.class.name}"
        assert endpoint.match?(URI.regexp), "`#{endpoint}` is not a valid URI"
      end
    end

    test do
      title 'token_endpoint_auth_methods_supported field'
      description %(
        If present, `token_endpoint_auth_methods_supported` must contain a fixed
        array with one string element: `["private_key_jwt"]`
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('token_endpoint_auth_methods_supported')

        assert config['token_endpoint_auth_methods_supported'] == ['private_key_jwt'],
               "`token_endpoint_auth_methods_supported` field must contain an array " \
               "with one string element 'private_key_jwt'"
      end
    end

    test do
      title 'token_endpoint_auth_signing_alg_values_supported field'
      description %(
        If present, `token_endpoint_auth_signing_alg_values_supported` is an
        array of one or more strings identifying signature algorithms
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('token_endpoint_auth_signing_alg_values_supported')

        assert_array_of_strings(config, 'token_endpoint_auth_signing_alg_values_supported')
      end
    end

    test do
      title 'registration_endpoint field'
      description %(
        If present, `registration_endpoint` is a string containing the URL of
        the Authorization Server's registration endpoint
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('registration_endpoint')

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
        an array of one or more strings identifying signature algorithms
      )

      input :config_json

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('registration_endpoint_jwt_signing_alg_values_supported')

        assert_array_of_strings(config, 'registration_endpoint_jwt_signing_alg_values_supported')
      end
    end

    test do
      title 'signed_metadata field'
      description %(
        If present, `signed_metadata` is a string containing a JWT
      )

      input :config_json
      output :signed_metadata_jwt

      run do
        assert_valid_json(config_json)
        config = JSON.parse(config_json)

        omit_if !config.key?('signed_metadata')
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
        TODO
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
  end
end
