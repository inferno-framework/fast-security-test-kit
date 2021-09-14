require_relative 'fast_security/discovery_group'

module FASTSecurity
  class Suite < Inferno::TestSuite
    id :fast_security
    title 'FAST Security'
    description 'Tests for FAST Security'

    group from: :discovery_group
  end
end
