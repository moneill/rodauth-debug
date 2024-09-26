# frozen_string_literal: true

require "sequel/core"

class RodauthMain < Rodauth::Rails::Auth
  configure do
    # List of authentication features that are loaded.
    enable :create_account, :verify_account, #:verify_account_grace_period,
           :login, :logout, :remember, :reset_password, :change_password,
           :change_password_notify, :change_login, :verify_login_change,
           :json

    enable :internal_request if Rails.env.test?

    # See the Rodauth documentation for the list of available config options:
    # https://github.com/jeremyevans/rodauth/blob/master/doc/base.rdoc

    # ==> General
    # Initialize Sequel and have it reuse Active Record's database connection.
    db Sequel.sqlite(extensions: :activerecord_connection, keep_reference: false)

    # Avoid DB query that checks accounts table schema at boot time.
    # See https://github.com/janko/rodauth-rails/discussions/268#discussioncomment-8250205
    convert_token_id_to_integer? false

    # Customize labels, refer to
    # https://github.com/jeremyevans/rodauth/blob/master/doc/base.rdoc
    login_label "Email Address"
    login_button "Log In"

    # Specify the controller used for view rendering, CSRF, and callbacks.
    rails_controller { RodauthController }

    # Make built-in page titles accessible in your views via an instance variable.
    title_instance_variable :@page_title

    # Store account status in an integer column without foreign key constraint.
    account_status_column :status

    # Store password hash in a column instead of a separate table.
    account_password_hash_column :password_hash

    # Set password when creating account instead of when verifying.
    verify_account_set_password? false

    # Change some default param keys.
    login_param "email"
    login_confirm_param "email-confirm"
    # password_confirm_param "confirm_password"

    # JWT Settings
    # jwt_secret { ENV["JWT_SECRET"] }

    # Redirect back to originally requested location after authentication.
    # login_return_to_requested_location? true
    # two_factor_auth_return_to_requested_location? true # if using MFA

    # Autologin the user after they have reset their password.
    # reset_password_autologin? true

    # Delete the account record when the user has closed their account.
    # delete_account_on_close? true

    # Redirect to the app from login and registration pages if already logged in.
    # already_logged_in { redirect login_redirect }

    # ==> Emails
    email_from "Test <test@localhost>"

    send_email do |email|
      # queue email delivery on the mailer after the transaction commits
      db.after_commit { email.deliver_later }
    end

    # ==> Flash
    # Match flash keys with ones already used in the Rails app.
    # flash_notice_key :success # default is :notice
    # flash_error_key :error # default is :alert

    # Override default flash messages.
    # create_account_notice_flash "Your account has been created. Please verify your account by
    #   visiting the confirmation link sent to your email address."
    require_login_error_flash "Please log in or sign up to continue"
    # login_notice_flash nil

    # ==> Validation
    # Override default validation error messages.
    # no_matching_login_message "user with this email address doesn't exist"
    already_an_account_with_this_login_message "an account with this email address already exists"
    # password_too_short_message { "needs to have at least #{password_minimum_length} characters" }
    # login_does_not_meet_requirements_message { "invalid email#{", #{login_requirement_message}"
    #   if login_requirement_message}" }

    # Passwords shorter than 8 characters are considered weak according to OWASP.
    password_minimum_length 8
    # bcrypt has a maximum input length of 72 bytes, truncating any extra bytes.
    password_maximum_bytes 72

    # Custom password complexity requirements (alternative to password_complexity feature).
    # password_meets_requirements? do |password|
    #   super(password) && password_complex_enough?(password)
    # end
    # auth_class_eval do
    #   def password_complex_enough?(password)
    #     return true if password.match?(/\d/) && password.match?(/[^a-zA-Z\d]/)
    #     set_password_requirement_error_message(:password_simple, "requires one number and one special character")
    #     false
    #   end
    # end

    # ==> Remember Feature
    # Remember all logged in users.
    after_login { remember_login }

    # Or only remember users that have ticked a "Remember Me" checkbox on login.
    # after_login { remember_login if param_or_nil("remember") }

    # Extend user's remember period when remembered via a cookie
    extend_remember_deadline? true

    create_verify_account_email do
      RodauthMailer.verify_account(self.class.configuration_name, account_id, verify_account_key_value)
    end

    # Perform additional actions after the account is created.
    # Doing this here will leverage Rails, rather than Sequel, to process
    # the update, which allows us to use Lockbox to encrypt the name fields
    after_create_account do
      @post_verify_redirect_path = session[login_redirect_session_key]
    end

    # Redirect to the email verification page after account creation
    # Append the redirect path to the URL so it can be accessed in the
    # verification step; can't use session because it gets blown away
    create_account_redirect do
      if defined?(@post_verify_redirect_path) && @post_verify_redirect_path.present?
        verify_account_email_link + "&redirect=#{@post_verify_redirect_path}"
      else
        verify_account_email_link
      end
    end

    # Wait 60 seconds between resending the verification email
    verify_account_skip_resend_email_within { 15.seconds }

    verify_account_email_recently_sent_redirect do
      verify_account_email_link
    end

    verify_account_email_sent_redirect do
      verify_account_email_link
    end

    # Do additional cleanup after the account is closed.
    # after_close_account do
    #   Profile.find_by!(account_id: account_id).destroy
    # end

    # ==> Redirects
    # Redirect to home page after logout.
    logout_redirect "/"

    # Redirect to login page after password reset.
    reset_password_redirect { login_path }

    # Ensure requiring login follows login route changes.
    require_login_redirect { login_path }

    # Take user back to the URL they were trying to access once they've auth'd
    # See https://github.com/jeremyevans/rodauth/blob/master/doc/guides/login_return.rdoc
    login_return_to_requested_location? true

    # ==> Deadlines
    # Change default deadlines for some actions.
    # verify_account_grace_period 10.seconds.to_i
    # reset_password_deadline_interval Hash[hours: 6]
    # verify_login_change_deadline_interval Hash[days: 2]
    # remember_deadline_interval Hash[days: 30]

    # Email verification code logic
    # See https://groups.google.com/g/rodauth/c/eBQem6q3Ne0/m/4jsJK7EZAwAJ
    verify_account_email_sent_notice_flash "A verification code has been sent to your email. " \
                                           "Please enter that code below."

    before_verify_account_route do
      Rails.logger.info { "[RODAUTH DEBUG] Inside before_verify_account_route"}
      # See https://github.com/janko/rodauth-rails/discussions/249#discussioncomment-7722233
      if request.get?
        session[:verify_account_redirect] = param("redirect")
      elsif request.post?
        @verify_account_redirect = session[:verify_account_redirect]
      end

      redirect "/success" if rails_account&.verified?
      request.get { verify_account_view }
    end

    account_from_verify_account_key do |key|
      unless timing_safe_eql?(key, rails_account.verification_key.key)
        verify_account_key_error "Invalid verification key."
      end

      if rails_account.verification_key.requested_at <= 1.hour.ago
        regenerate_verify_account_key
        verify_account_email_resend
        verify_account_key_error "This verification key has expired. We've sent a new code to #{rails_account.email}."
      end

      account_from_session
    end

    before_verify_account_email_resend { regenerate_verify_account_key }

    # Redirect to wherever login redirects to after account verification.
    verify_account_redirect do
      if special_user_agent?
        "/special-user-agent-success"
      elsif defined?(@verify_account_redirect) && @verify_account_redirect.present?
        @verify_account_redirect
      else
        "/success"
      end
    end
  end

  private

  def verify_account_key_error(message)
    set_field_error("key", message)
    set_response_error_status(422)
    return_response verify_account_view
  end

  def regenerate_verify_account_key
    rails_account.verification_key.update!(key: random_verify_key, requested_at: Time.zone.now)
  end

  def generate_verify_account_key_value
    @verify_account_key_value = random_verify_key
  end

  def random_verify_key
    Array.new(6) { rand(10) }.join
  end
end
