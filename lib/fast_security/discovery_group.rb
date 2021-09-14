# coding: utf-8
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
      title 'CapabilityStatement indicates UDAP support'
      description %(
        CapabilityStatement **SHALL** include the following code in the
        `rest.security.service` list:
        `http://fhir.udap.org/CodeSystem/capability-rest-security-service|UDAP`.
      )

      input :url
      # Named requests can be used by other tests
      makes_request :capabilities

      fhir_client { url :url }

      run do
        fhir_get_capability_statement(name: :capabilities)

        assert_response_status(200)
        assert_valid_json(response[:body])
        assert_resource_type(:capability_statement)

        udap_service_listed =
          resource&.rest&.any? do |rest|
            rest.security&.service.any? do |service|
              service.coding.any? do |coding|
                coding.code == 'http://fhir.udap.org/CodeSystem/capability-rest-security-service|UDAP'
              end
            end
          end

        assert udap_service_listed, 'UDAP service not included in rest.security.service'
      end
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
        get("#{url.chomp('/')}/.well-known/udap", name: :config)
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

        pass_if !config.key?('udap_certifications_supported')

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

        pass_if !config.key?('udap_certifications_required')

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

        pass_if !config.key?('grant_types_supported')

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

        pass_if !config.key?('scopes_supported')

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

        pass_if !config.key?('authorization_endpoint')

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

        pass_if !config.key?('token_endpoint')

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

        pass_if !config.key?('token_endpoint_auth_methods_supported')

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

        pass_if !config.key?('token_endpoint_auth_signing_alg_values_supported')

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

        pass_if !config.key?('registration_endpoint')

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

        pass_if !config.key?('registration_endpoint_jwt_signing_alg_values_supported')

        assert_array_of_strings(config, 'registration_endpoint_jwt_signing_alg_values_supported')
      end
    end
  end
end
