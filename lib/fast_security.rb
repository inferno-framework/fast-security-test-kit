require_relative 'fast_security/discovery_group'

module FASTSecurity
  class Suite < Inferno::TestSuite
    id :fast_security
    title 'FAST Security'
    description %(
      The FAST Security Suite verifies that systems correctly implement the
      [FAST Security FHIR® IG](http://hl7.org/fhir/us/udap-security/STU1/)
      for extending OAuth 2.0 using UDAP workflows. Currently, only the
      [discovery
      requirements](http://hl7.org/fhir/us/udap-security/STU1/discovery.html)
      are tested, verifying the presence of metadata which represents server
      capabilities. The tested metadata includes all required, optional,
      recommended, and conditional parameters except for the optional
      `community` parameter.

      Complete testing of compliance with the FAST Security IG will require
      testing of
      [registration](http://hl7.org/fhir/us/udap-security/STU1/registration.html),
      authorization and authentication of [consumer-facing
      apps](http://hl7.org/fhir/us/udap-security/STU1/consumer.html)
      and [B2B
      apps](http://hl7.org/fhir/us/udap-security/STU1/b2b.html),
      and [tiered OAuth for user
      authentication](http://hl7.org/fhir/us/udap-security/STU1/user.html).
    )

    group from: :discovery_group
  end
end
