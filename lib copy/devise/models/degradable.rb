require "devise/hooks/degradable"

module Devise
  module Models
    # Handles delaying a user access more and more by the failed number of attempts.
    # Accepts one strategy and that is to degrade the service little by little.
    # This means that the user will have to wait more and more to 'guess' his/her
    # password - the goal being to protect against brute force attacks.
    # In case the password is correctly entered then the user will be logged in imediately.
    #
    # == Options
    #
    # Degradable adds the following options to +devise+:
    #
    #   * +degrade_strategy+: degrades the service by :failed_attempts or :none.
    #
    module Degradable
      extend  ActiveSupport::Concern

      delegate :degrade_strategy_enabled?, to: "self.class"

      def self.required_fields(klass)
        attributes = []
        attributes << :failed_attempts if klass.degrade_strategy_enabled?(:failed_attempts)

        attributes
      end

      # Reseting the service degradation for a user by cleaning the failed_attempts.
      def reset_service_degradation!
        self.failed_attempts = 0 if respond_to?(:failed_attempts=)
        save(validate: false)
      end

      # Verifies whether the user service was degraded or not.
      def service_degraded?
        self.failed_attempts > 0
      end

      # Overwrites valid_for_authentication? from Devise::Models::Authenticatable
      # for verifying whether a user is allowed to sign in or not.
      def valid_for_authentication?
        return super unless persisted? && degrade_strategy_enabled?(:failed_attempts)

        if super
          reset_service_degradation!

          true
        else
          self.failed_attempts ||= 0
          self.failed_attempts += 1

          save(validate: false)

          sleep self.failed_attempts * Devise.degrade_increment

          false
        end
      end

      protected

      module ClassMethods

        # Is the degrade enabled for the given degrade strategy?
        def degrade_strategy_enabled?(strategy)
          self.degrade_strategy == strategy
        end

        Devise::Models.config(self, :degrade_strategy)
      end
    end
  end
end
