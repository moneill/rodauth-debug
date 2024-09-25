class HomeController < ApplicationController
  
  before_action :authenticate
  
  def index
    render plain: "Hello, index"
  end
  
  def success
    render plain: "Success"
  end
  
  def special_user_agent_success
    render plain: "Special success page"
  end
end
