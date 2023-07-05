require_relative 'fast_security/discovery_group'

module FASTSecurity
  class Suite < Inferno::TestSuite
    id :fast_security
    title 'FAST Security'
    description %( The FAST Security Suite verifies that systems correctly implement 
      the [FAST Security IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/) 
      for extending OAuth 2.0 using UDAP workflows. Currently, only the 
      [discovery requirements](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html) are
      tested by the first test group, verifying the presence of metadata which 
      represents server capabilities. The tested metadata includes all required, optional, recommended, and conditional
      parameters. It does not, however, test for the support of the optional `community` parameter
      to get a certificate intended for use within the identified trust community.
      Complete testing of compliance with the FAST Security IG will require testing of 
      [registration](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/registration.html),
      authorization and authentication of [consumer-facing apps](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/consumer.html)
      and [B2B apps](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/b2b.html), 
      [tiered user authentication](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/user.html),
      and additional conformance to [FHIR artifacts](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/artifacts.html) (TBD). 
    )

    group from: :discovery_group
  end
end
