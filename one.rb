require "net/http"
require "uri"
require "securerandom"

class Spider
  def initialize(url: nil, inbound: true)
    @UserAgents = [
      "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
      "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
      "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; TheWorld)",
      "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+",
      "Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; zh-TW) AppleWebKiwt/534.8+ (KHTML, like Gecko) Version/6.0.0.448 Mobile Safari/534.8+",
    ]

    @Agent = @UserAgents.sample
    @Urls = []
    @Visited = []
    @Cookies = {}
    @Intresting = [] # XSS, SQLi, LFI etc
    @Information = [] # Emails, Phone Numbers etc
    @target = url
    @targetUrl = uri(@target)
    @IgnoreList = %w[
      css
      js
      jpg
      jpeg
      png
      gif
      ico
      svg
      ttf
      woff
      woff2
      eot
      otf
      mp4
      mp3
      pdf
    ]
    @Payloads = {
      "LFI" => /(?i)[^\n]{0,100}(no such file|failed (to )?open)[^\n]{0,100}/,
      "XSS" => "<'\">",
      "SQLi" => {
        "Injections" => ["'", '"', ")", "(", ",", ".", "--", ";"],
        "Exceptions" => ["There's an issue", "unknown error", "syntax error", "unclosed quotation mark", "database error"],
      },
      "Email" => /^[^@]+@[^@]+\.[^@]+$/,
    }

    # @FileInclusionRegex = /(?i)[^\n]{0,100}(no such file|failed (to )?open)[^\n]{0,100}/

    log(level: :info, message: "No URL provided? (what r u trying to do bro)") if url.nil?
  end

  def log(level: :info, message: "", msg: "", code: nil)
    timestamp = Time.now.strftime("%H:%M:%S")
    case level
    when :info
      puts("\e[32m[INFO]\e[0m [#{timestamp}] #{message}")
    when :error
      puts("\e[31m[ERROR]\e[0m [#{timestamp}] #{message}")
    when :httplog
      puts("\e[34m[HTTP]\e[0m [#{timestamp}] #{message} (#{color(code)})")
    else
      puts("\e[34m[DEBUG]\e[0m [#{timestamp}] #{message}")
    end
  end

  def color(code)
    case code
    when "200"
      "\e[32m#{code}\e[0m"
    when "301" || "302" || "303" || "307" || "308"
      "\e[34m#{code}\e[0m"
    when "404"
      "\e[33m#{code}\e[0m"
    when "500" || "501" || "502" || "503" || "504" || "505"
      "\e[31m#{code}\e[0m"
    when "403" || "401" || "406" || "405"
      "\e[31m#{code}\e[0m"
    when "400"
      "\e[33m#{code}\e[0m"
    else
      code
    end
  end

  def uri(path)
    begin
      path = path.to_s if path.is_a?(URI)
      if path =~ /^http/
        URI.parse(path)
      elsif path =~ /^\/\//
        URI.join(@target, path)
      elsif path.include?("#")
        # Not an actual URL
        URI.parse(path.split("#").first)
      else
        URI.join(@target, path)
      end
    rescue URI::InvalidURIError
      nil
    end
  end

  def normalizeURL(url)
    uri = uri(url)
    return nil if uri.nil?
    uri.query = nil
    uri.fragment = nil
    uri.to_s
  end

  def fetch(uri, headers: {}, parameters: {})
    request = Net::HTTP::Get.new(uri)
    request["User-Agent"] = @Agent
    if @Cookies.any?
      request["Cookie"] = @Cookies.map { |k, v| "#{k}=#{v}" }.join("; ")
    end
    headers.each { |k, v| request[k] = v }
    request.set_form_data(parameters) if parameters.any?

    host = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https",
                                                   verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      http.request(request)
    end
    host["set-cookie"]&.split("; ")&.each do |cookie|
      key, value = cookie.split("=")
      @Cookies[key] = value
    end
    host
  rescue StandardError => e
    log(level: :error, message: "Failed to fetch #{uri} - #{e}")
    nil
  end

  def inbound?(target)
    begin
      target = uri(target) if target.is_a?(String)
      return false unless target.is_a?(URI::HTTP) || target.is_a?(URI::HTTPS)

      target.host == @targetUrl.host
    rescue => e
      false
    end
  end

  attr_accessor :target, :targetUrl, :Urls, :Visited, :Cookies, :Intresting, :IgnoreList, :Information, :ExcludeList

  def checksHeuristic(uri, params)
    params.each do |param|
      reflectionPayload = SecureRandom.hex(16)
      new_uri = uri.dup
      new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, reflectionPayload] : [k, v] })
      request = fetch(new_uri)
      if request.code == "200" && request.body.include?(reflectionPayload)
        log(level: :info, message: "Reflected Input at Parameter(#{param[0]}) in URL(#{new_uri})")

        payload = "#{SecureRandom.hex(16)}#{@Payloads["XSS"]}#{SecureRandom.hex(16)}"
        new_uri = uri.dup
        new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, payload] : [k, v] })
        request = fetch(new_uri)
        if request.code == "200" && request.body.include?(payload)
          log(level: :info, message: "Heuristic Checks found that Parameter(#{param[0]}) from URL(#{new_uri}) might be vulnerable to XSS")
          @Intresting << { url: new_uri, param: param[0], payload: payload }
          # @Intresting << { url: new_uri, param: param[0], payload: payload }
        end
      end

      if request.code == "200" && request.body.match(@Payloads["LFI"])
        log(level: :info, message: "Heuristic Checks found that Parameter(#{param[0]}) from URL(#{new_uri}) might be vulnerable to LFI")
        @Intresting << { url: new_uri, param: param[0], payload: "File Inclusion" }
        # log(level: :info, message: "File Inclusion found at #{new_uri} with param #{param[0]}")
        # @Intresting << { url: new_uri, param: param[0], payload: "File Inclusion" }
      end

      sqliCheck(uri, params, param)
    end
  end

  def sqliCheck(uri, params, param)
    # sqli_chars = ["'", '"', ")", "(", ",", ".", "--", ";"]
    # format_exception_strings = ["There's an issue", "unknown error", "syntax error", "unclosed quotation mark", "database error"]

    @Payloads["SQLi"]["Injections"].each do |char|
      value = param[1] + char
      new_uri = uri.dup
      new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, value] : [k, v] })
      request = fetch(new_uri)
      page = request.body

      if @Payloads["SQLi"]["Exceptions"].any? { |str| page.include?(str) } || (param[1].match?(/^\d+$/) && blindSQLiDetect?(new_uri, params, param, char))
        log(level: :info, message: "Heuristic Checks found that Parameter(#{param[0]}) from URL(#{new_uri}) might be vulnerable to SQL-Injection : #{char}")
        @Intresting << { url: new_uri, param: param[0], payload: char }
        break # Break the loop if found
      end
    end
  end

  def blindSQLiDetect?(uri, params, param, char)
    rand_int = SecureRandom.random_number(10)
    new_value = "#{param[1].to_i + rand_int}-#{rand_int}"
    new_uri = uri.dup
    new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, "#{new_value}#{char}"] : [k, v] })
    request = fetch(new_uri)
    page = request.body

    if page.include?(new_value)
      rand_str = SecureRandom.hex(10)
      new_value = "#{param[1]}.#{SecureRandom.random_number(9) + 1}#{rand_str}"
      new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, "#{new_value}#{char}"] : [k, v] })
      request = fetch(new_uri)
      return request.body.include?(new_value)
    end
    false
  end

  def isValidPhoneNumber?(phone)
    phone.match?(/^\d{10,14}$/)
  end

  def isValidEmail?(email)
    email.match?(@Payloads["Email"])
    #  email.match?(/(?:(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/)
  end
end

out = {}
valid = %w[url inbound exclude fillempty]
ARGV.each do |arg|
  next unless arg.start_with?("--") || arg.start_with?("-")

  key, value = arg.split("=")
  key = key[2..]
  out[key] = value
  unless valid.include?(key)
    puts("> Not sure what to do with `\e[1m#{key}\e[0m` - ignoring")
    out.delete(key)
  end
end

# if out["url"].nil? || out["url"].empty?
#   puts("URL is required")
#   exit 1
# end

if out.empty?
  puts("Usage: ruby one.rb --url=https://example.com [--inbound=true]")
  exit 1
elsif out["url"].nil?
  puts("URL is required")
  exit 1
elsif out["url"].empty?
  puts("URL is empty")
  exit 1
end

exit 1 if out.empty?

main = Spider.new(url: out["url"])

if out["exclude"].nil? # Exclude list
  out["exclude"] = ""
else
  main.log(level: :info, message: "Excluding file types .. [#{out["exclude"]}]")
  out["exclude"] = out["exclude"].downcase
  # Add new file types to the list
  main.IgnoreList = main.IgnoreList + out["exclude"].split(",")
end

if out["fillempty"].nil? # Fill empty parameters with random values
  out["fillempty"] = "false"
else
  main.log(level: :info, message: "Filling empty parameters with random values .. [#{out["fillempty"]}]")
  # puts("Filling empty parameters with random values .. [#{out["fillempty"]}]")
  out["fillempty"] = out["fillempty"].downcase
end

main.log(level: :info, message: "Starting crawling against #{out["url"]}... [gimme a second]")

begin
  request = main.fetch(main.targetUrl)
  if request.is_a?(Net::HTTPRedirection) || request.is_a?(Net::HTTPMovedPermanently) || request.is_a?(Net::HTTPFound)
    if request["location"].nil?
      main.log(level: :error, message: "Redirected to an empty location? (#{request.code})")
    else
      main.targetUrl = main.uri(request["location"])
      main.log(level: :info, message: "Redirected to #{main.targetUrl} .. set as new target")
    end
  elsif request.code == "404"
    main.log(level: :error, message: "404 page not found for #{main.targetUrl}")
    exit 1
  else
    main.log(level: :httplog, message: "Fetched #{main.targetUrl}", code: request.code)
  end
rescue StandardError => e
  main.log(level: :error, message: "Failed to fetch #{main.targetUrl} - #{e}")
end

main.Urls << main.targetUrl

while main.Urls.any?
  url = main.Urls.shift
  next if url.nil?
  begin
    normalized_url = main.normalizeURL(url)
    normal = main.uri(normalized_url)
    if File.extname(normal.path)
      ext = normal.path.split(".")
      if main.IgnoreList.include?(ext[-1])
        next
      end
    end

    next if main.Visited.include?(normalized_url)
  rescue => e
    # main.log(level: :error, message: "Something went wrong.. skipping..")
    next # Silent Error
  end
  main.Visited << normalized_url
  #  next if main.Visited.include?(url)
  # main.Visited << url
  uri = main.uri(url)
  next if uri.nil?

  begin
    request = main.fetch(uri)
    next if request.nil?

    if request.is_a?(Net::HTTPRedirection) || request.is_a?(Net::HTTPMovedPermanently) || request.is_a?(Net::HTTPFound)
      if request["location"].nil?
        main.log(level: :error, message: "Possibly broken redirect at #{url} (#{request.code})")
      else
        new_url = main.uri(request["location"])
        main.log(level: :httplog, message: "#{url} ~> #{new_url}", code: request.code, msg: request.message)
        uri = new_url
      end
    else
      main.log(level: :httplog, message: "#{url} - #{request.message}", code: request.code)
    end
  end

  next if uri.nil?
  unless uri.query.nil?
    params = URI.decode_www_form(uri.query)
    # puts "#{uri} => #{params}"
    if out["fillempty"] == "true"
      params.map! { |k, v| v.empty? ? [k, SecureRandom.hex(16)] : [k, v] } # Fill empty parameters with random values
    end

    main.checksHeuristic(uri, params)
  end

  next unless request.code == "200"
  body = request.body
  next unless body.include?("href")
  # URL's
  body.scan(/href=["'](.*?)["']/).flatten.each do |link|
    next if link.nil? || link.empty?
    if out["inbound"] == "false"
      main.Urls << link
      next
    end
    next unless main.inbound?(link)
    main.Urls << link
  end
  # # Forms
  # body.scan(/<form.*?action=["'](.*?)["']/).flatten.each do |form|
  #   next if form.nil? || form.empty?
  #   # puts form

  #   if out["inbound"] == "false"
  #     main.Urls << form
  #     next
  #   end
  #   next unless main.inbound?(form)
  #   main.Urls << form
  # end

  begin
    forms = body.scan(/<form.*?action=["'](.*?)["'].*?method=["'](.*?)["'].*?>.*?<\/form>/im)

    forms.each do |form|
      action = form[0]
      method = form[1].nil? || form[1].empty? ? "GET" : form[1].upcase
      # Extract input elements
      inputs = body.scan(/<input.*?name=["'](.*?)["'].*?>/i).flatten
      # Update URI based on method
      form_uri = URI.join(uri, action)
      if method == "GET"
        # Adjust the query string based on inputs' names
        query_hash = URI.decode_www_form(form_uri.query || "") + inputs.map { |i| [i, ""] }
        form_uri.query = URI.encode_www_form(query_hash)
      end
      # Add the form to the list of URLs to be tested
      next if main.Urls.include?(form_uri.to_s)
      # puts form_uri.to_s
      main.Urls << form_uri.to_s
    end
  rescue => e
    # Silent Error
    next
  end

  # Emails (mailto)
  body.scan(/mailto:(.*?)[\?"]/).flatten.each do |email|
    next if email.nil? || email.empty?
    # Next if already found
    next if main.Information.any? { |i| i[:value] == email }
    if main.isValidEmail?(email)
      main.Information.push(
        {
          type: "email",
          path: uri,
          value: email,
        }
      )
      main.log(level: :info, message: "Found email address: #{email}")
    end
  end
  # Phone Numbers
  body.scan(/tel:(.*?)[\?"]/).flatten.each do |phone|
    next if phone.nil? || phone.empty?
    next if main.Information.any? { |i| i[:value] == phone }
    if main.isValidPhoneNumber?(phone)
      main.Information.push(
        {
          type: "phone",
          path: uri,
          value: phone,
        }
      )
      main.log(level: :info, message: "Found phone number: #{phone}")
    end
  end
end
# Draw a Line #
main.log(level: :info, message: "-" * 50)
main.log(level: :info, message: "Crawling completed..")
main.log(level: :info, message: "Intresting URLs: #{main.Intresting.count}")
main.log(level: :info, message: "Information found: #{main.Information.count}")
main.log(level: :info, message: "Visited URLs: #{main.Visited.count}")
main.log(level: :info, message: "Total URLs: #{main.Urls.count}")
main.log(level: :info, message: "Total Cookies: #{main.Cookies.count}")

main.log(level: :info, message: "-" * 50)

main.Intresting.each do |i|
  main.log(level: :info, message: "Intresting URL: #{i[:url]}")
  main.log(level: :info, message: "Parameter: #{i[:param]}")
  main.log(level: :info, message: "Payload: #{i[:payload]}")
end

main.log(level: :info, message: "-" * 50)

main.Information.each do |i|
  main.log(level: :info, message: "Information Type: #{i[:type]}")
  main.log(level: :info, message: "Path: #{i[:path]}")
  main.log(level: :info, message: "Value: #{i[:value]}")
end

exit 0
