
class Requester
  def fetch(uri, headers: {}, parameters: {}, agent: @Agent)
    request = Net::HTTP::Get.new(uri)
    request["User-Agent"] = agent
    request["Cookie"] = @settings[:cookie]
    headers.each do |key, value|
      request[key] = value
    end
    request.set_form_data(parameters) if parameters.any?
    host = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      http.request(request)
    end
    host
  rescue => e
    # log(level: :error, message: "Error fetching URL: #{uri}\n#{e}\n#{e.backtrace}")
    nil
  end

  def heuristic(uri, params)
    params.each do |param|
      # Check : Reflection
      reflectPay = SecureRandom.hex(8)
      newUri = uri.dup
      newUri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, reflectPay] : [k, v] })
      # newUri.query = URI.encode_uri_component(params.map { |k, v| k == param[0] ? [k, reflectPay] : [k, v] }.to_h)
      req = fetch(newUri)
      if req.body.include?(reflectPay)
        log(level: :heuristicXSS, message: "Reflection found in: #{uri} (#{param[0]})") if @settings[:logreflection]
        xssPay = "#{SecureRandom.hex(8)}<'\">#{SecureRandom.hex(8)}"
        newUri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, xssPay] : [k, v] })
        # newUri.query = URI.encode_uri_component(params.map { |k, v| k == param[0] ? [k, xssPay] : [k, v] }.to_h)
        req = fetch(newUri)
        if req.body.include?(xssPay)
          log(level: :heuristicXSS, message: "XSS found in: #{uri} (#{param[0]})")
          @vulnerable << { url: uri, type: "XSS", payload: xssPay, response: "Reflection Of Payload Vector (<'\">)", param: param[0] }
        end
      end
      # Check LFI
      if req.body.match?(/(?i)[^\n]{0,100}(no such file|failed (to )?open)[^\n]{0,100}/)
        log(level: :heuristicLFI, message: "LFI found in: #{uri} (#{param[0]}) - Reflection Of Payload Vector (no such file)")
        @vulnerable << { url: uri, type: "LFI", payload: "", response: "Reflection Of Payload Vector (no such file)", param: param[0] }
      elsif uri.path.include?("../")
        log(level: :heuristicLFI, message: "LFI found in: #{uri} (#{param[0]}) - Reflection Of Payload Vector (../)")

        @vulnerable << { url: uri, type: "LFI", payload: "", response: "Reflection Of Payload Vector (../)", param: param[0] }
      end
    end
  rescue => e
    log(level: :error, message: "Error in heuristic: #{uri}\n#{e}\n#{e.backtrace}")
  end

  def dork(query, page = 0)
    cookie = "CONSENT=YES+shp.gws-#{Time.new.strftime("%Y%m%d")}-0-RC1.#{SecureRandom.alphanumeric(2).downcase}+FX+740"
    uri = "https://www.google.com/search?q=#{URI.encode_uri_component(query)}&num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search&start=#{page}"
    uri = URI.parse(uri)
    req = fetch(uri, headers: { "Cookie" => cookie }, agent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0")
    if req.nil? || req.body.nil?
      log(level: :error, message: "Error in dork: #{query}")
      return []
    end
    if req.body.include?("Our systems have detected unusual traffic")
      log(level: :error, message: "Google has detected unusual traffic, please try again later.")
      exit 1
    end
    page = req.body
    page = page.gsub(/\\x([0-9A-Fa-f]{2})/) { |match| $1.hex.chr }
    page = CGI.unescapeHTML(page)
    page.gsub!(/<script.*?>.*?<\/script>/m, "")
    page.gsub!(/<style.*?>.*?<\/style>/m, "")
    page.gsub!(/&nbsp;/, " ")
    page.gsub!(/&amp;/, "&")
    found = page.scan(/href="\/url\?esrc=s&q=&rct=j&sa=U&url=([^&]+)&ved=[^"]+" data-ved="[^"]+"/).flatten
  rescue => e
    log(level: :error, message: "Error in dork: #{query}\n#{e}\n#{e.backtrace}")
    []
  end

  def extract(body)
    # Extracts all links and forms from page
    # Forms are formatted into url's with parameters (if GET)
    links = []
    urls = body.scan(/href="([^"]+)"/).flatten.uniq.map { |url| url.gsub(/&amp;/, "&") }
    urls.each do |url|
      begin
        uri = URI.parse(url)
        next if uri.host.nil?
        links << uri
      rescue URI::InvalidURIError
        next
      end
    end
    forms = body.scan(/<form.*?>.*?<\/form>/m).flatten
    forms.each do |form|
      begin
        # Check for method GET/get
        method = form.match(/method=["']?([^"'>]+)/i)
        next if method.nil?
        next unless method[1].downcase == "get"
        # Check for action
        action = form.match(/action=["']?([^"'>]+)/i)
        next if action.nil?
        action = action[1]
        # Check for inputs
        inputs = form.scan(/<input.*?>/i)
        next if inputs.empty?
        params = {}
        inputs.each do |input|
          name = input.match(/name=["']?([^"'>]+)/i)
          next if name.nil?
          name = name[1]
          value = input.match(/value=["']?([^"'>]+)/i)
          value = value.nil? ? "" : value[1]
          params[name] = value
        end
        uri = URI.parse(action)
        links << uri
      end
    end
  end

  def spider(uri, threads)
    strart = Time.now
    pages = [
      uri,
    ]
    visited = []
    while pages.any?
      current = pages.pop # Get the last page
      begin
        stamp = Time.now
        req = fetch(current)
        stamp = Time.now - stamp # How long it took to fetch
        next if req.nil?
        next if req.body.nil?
        visited << current
        links = extract(req.body)
        links.each do |link|
          next if visited.include?(link)
          next if pages.include?(link)
          next unless inscope?(link, uri)
          pages << link
        end
      rescue => e
      end
    end
  end
end
