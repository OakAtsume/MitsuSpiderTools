require("net/http")
require("uri")
require("securerandom")

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
    @Intresting = []
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
    ]

    log(level: :info, message: "No URL provided? (what r u trying to do bro)") if url.nil?
  end

  def log(level: :info, message: "", msg: "", code: nil)
    timestamp = Time.now.strftime("%H:%M:%S")
    # alignment = "\t" * (3 - level.to_s.length / 4)
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
    when "404"
      "\e[33m#{code}\e[0m"
    when "500"
      "\e[31m#{code}\e[0m"
    when "301"
      "\e[34m#{code}\e[0m"
    when "403"
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

  def fetch(uri, headers: {}, parameters: {})
    request = Net::HTTP::Get.new(uri)
    request["User-Agent"] = @Agent
    request["Cookie"] = @Cookies.map { |k, v| "#{k}=#{v}" }.join("; ")
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
    target = uri(target) if target.is_a?(String)
    return false unless target.is_a?(URI::HTTP) || target.is_a?(URI::HTTPS)

    target.host == @targetUrl.host
  end

  attr_accessor :target, :targetUrl, :Urls, :Visited, :Cookies, :Intresting, :IgnoreList
end

out = {}
valid = %w[url inbound]
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

exit 1 if out.empty?

main = Spider.new(url: out["url"])

main.log(level: :info, message: "Starting crawling agains't #{out["url"]}... [gimme a second]")

begin
  request = main.fetch(main.targetUrl)
  if request.is_a?(Net::HTTPRedirection) || request.is_a?(Net::HTTPMovedPermanently) || request.is_a?(Net::HTTPFound)
    if request["location"].nil?
      main.log(level: :error, message: "Redirected to an empty location? (#{request.code})")
    else
      main.targetUrl = main.uri(request["location"])
      main.log(level: :info, message: "Redirected to #{main.targetUrl} .. set as new target")
    end
    # 404 page
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
  next if url.nil? || main.Visited.include?(url)
  # next if main.IgnoreList.any? { |ext| url.end_with?(ext) }

  main.Visited << url
  uri = main.uri(url)
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

  # Check if there's any Parameters.
  if !uri.query.nil?
    params = URI.decode_www_form(uri.query)
    params.each do |param|
      # Check for Reflection #
      # If found then Check for XSS #
      reflectPayload = SecureRandom.hex(10)
      new_uri = uri.dup
      new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, reflectPayload] : [k, v] })
      request = main.fetch(new_uri)
      if request.code == "200" && request.body.include?(reflectPayload)
        main.log(level: :info, message: "Reflection found at #{new_uri} with param #{param[0]}")
        # Check for XSS #
        payload = "<'\">"
        new_uri = uri.dup
        new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, payload] : [k, v] })
        request = main.fetch(new_uri)
        if request.code == "200" && request.body.include?(payload)
          main.log(level: :info, message: "XSS found at #{new_uri} with param #{param[0]}")
          main.Intresting << { url: new_uri, param: param[0], payload: payload }
        end
      end

      # # Send a request with the parameter and XSS Payload
      # payload = "<'\">"
      # new_uri = uri.dup
      # new_uri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, payload] : [k, v] })
      # request = main.fetch(new_uri)
      # next unless request.code == "200"

      # body = request.body
      # next unless body.include?(payload)

      # main.Intresting << { url: new_uri, param: param[0], payload: payload }

    end
  end
  next unless request.code == "200"
  body = request.body
  next unless body.include?("href")

  body.scan(/href=["'](.*?)["']/).flatten.each do |link|
    next if link.nil? || link.empty?

    # Should we check for outbound links?
    if out["inbound"] == "false"
      main.Urls << link
      next
    end
    next unless main.inbound?(link)

    main.Urls << link
  end
end
