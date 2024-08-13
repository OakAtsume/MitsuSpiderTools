require("net/http")
require("uri")
require("cgi")
require("securerandom")

class Spider
  def initialize(cookie: "", threads: 5, inbound: true, logreflection: false)
    @UserAgents = [
      "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
      "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
      "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; TheWorld)",
      "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+",
      "Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; zh-TW) AppleWebKiwt/534.8+ (KHTML, like Gecko) Version/6.0.0.448 Mobile Safari/534.8+",
    ]
    @Agent = @UserAgents.sample
    @visited = [] # Base URL's of visited pages
    @vulnerable = [] # Records of Vulnerable pages { url: "http://example.com", type: "SQLi", payload: "1' OR 1=1 --", response: "" }
    @ignoredexts = %w[
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
      doc
      docx
      xls
      xlsx
      ppt
      pptx
    ]
    @threads = []
    @settings = {
      inbound: inbound.nil? ? true : inbound.to_s.downcase == "true" ? true : false,
      logreflection: logreflection,
      cookie: cookie,
      threads: threads,

    }
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
    when :heuristicXSS
      puts("\e[31m[HEURISTIC-XSS]\e[0m [#{timestamp}] #{message}")
    when :heuristicSQLi
      puts("\e[31m[HEURISTIC-SQLi]\e[0m [#{timestamp}] #{message}")
    when :heuristicLFI
      puts("\e[31m[HEURISTIC-LFI]\e[0m [#{timestamp}] #{message}")
    when :warning
      puts("\e[33m[WARNING]\e[0m [#{timestamp}] #{message}")
    else
      puts("\e[34m[DEBUG]\e[0m [#{timestamp}] #{message}")
    end
  end

  def color(code)
    case code
    when "200"
      "\e[32m#{code}\e[0m"
    when "301" || "302" || "303" || "307" || "308" || "307"
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

  def uri(path, base = nil) # Path = The URL to parse | Base = The base URL to use (incalculates relative URL's)
    begin
      # path = path.to_s if path.is_a?(URI)

      # raise if !base.is_a?(URI) && !base.nil? # If not a URI or nil, raise an error
      if path =~ /^http/
        URI.parse(path)
      elsif path =~ /^\/\//
        URI.join(base, path)
      elsif path.include?("#")
        URI.parse(path.split("#")[0])
      else
        begin
          URI.join(base, path)
        rescue => e
          # puts("Error: #{e} - #{path} \n #{e.backtrace}")
          nil
        end

        # URI.join(base, path)

      end
    rescue => e
      # log(level: :error, message: "Error parsing URL: #{path}\n#{e}\n#{e.backtrace}")
      nil
    end
  end

  def normalize(uri)
    nil if uri.nil?
    uri = uri.dup
    uri.fragment = nil
    uri.query = nil
    uri
  end

  # Stuff for the bot #
  def fetch(uri, headers: {}, parameters: {}, agent: @Agent)
    request = Net::HTTP::Get.new(uri)
    # Set timeout to 2 seconds

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
      # # Check for Dynamic Pages
      # dynamicPay = SecureRandom.hex(8)
      # newUri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, dynamicPay] : [k, v] })
      # dynamicReq = fetch(newUri)
      # if dynamicReq.body != req.body
      #   log(level: :heuristicDynamic, message: "Dynamic content detected in: #{uri} (#{param[0]})")
      #   @vulnerable << { url: uri, type: "Dynamic Content", payload: dynamicPay, response: "Content changes with payload", param: param[0] }
      # end

      # # Check for Passive SQLi
      # sqliPayloads = ["'", "\""]
      # sqliPayloads.each do |sqliPay|
      #   newUri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, sqliPay] : [k, v] })
      #   sqliReq = fetch(newUri)
      #   if sqliReq.body.match?(/(SQL syntax|Warning: mysql_|Unclosed quotation mark|quoted string not properly terminated|SQL error)/i)
      #     log(level: :heuristicSQLi, message: "SQLi found in: #{uri} (#{param[0]})")
      #     @vulnerable << { url: uri, type: "SQLi", payload: sqliPay, response: "SQL error message detected", param: param[0] }
      #   end
      # end

    end
  rescue => e
    log(level: :error, message: "Error in heuristic: #{uri}\n#{e}\n#{e.backtrace}")
  end

  def extractlinks(uri, body)
    links = []
    links = body.scan(/href=["'](.*?)["']/).flatten.each do |link|
      next if link.nil? || link.empty? || link.start_with?("#")
    end
    links
  end

  # def extractform(uri, body) # Cuz why not? :D

  # end

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

  def inscope?(uri, scope)
    begin
      if uri.nil? || scope.nil?
        return false
      end
      if uri.path.nil? || uri.path.empty?
        return false
      end

      # if !uri.path.start_with?("http") && !uri.path.start_with?("/")
      #   return false
      # end

      # Make sure it starts with http/https or is a relative URL

      if uri.is_a?(String)
        uri = URI.parse(uri)
      end
      if scope.is_a?(String)
        scope = URI.parse(scope)
      end
      # puts uri

      return true if uri.host == scope.host
      return true if uri.host.nil? && uri.path.start_with?("/")
      return true if uri.host.nil? && uri.path.start_with?("../")
      return true if uri.host.nil? && uri.path.start_with?("./")
    rescue => e
      # log(level: :error, message: "Error in inscope: #{uri} - #{scope}\n#{e}\n#{e.backtrace}")
      # puts("Go scream at Oak to fix this.")
    end
    false
  end

  def bot(id, url)
    id = id.to_i
    startTimestamp = Time.now
    pending = [url]
    visited = []
    tested = [] # Base URL's of pages already tested (avoid re-testing)
    scope = uri(url) # Scope of the URL (Main-Target)
    while pending.any?
      current = uri(pending.shift, scope) # Current URL to visit
      # next if current.nil? || visited.include?(current.to_s)

      # # next if current.nil? || visited.include?(current.to_s) || @ignoredexts.include?(current.path.split(".").last) || visited.include?(normalize(current).to_s)
      next if current.nil?
      next if visited.include?(current.to_s) || visited.include?(normalize(current).to_s)
      if !current.to_s.split(".").last.nil?
        next if @ignoredexts.include?(current.to_s.split(".").last)
      end
      

      # puts(@settings[:inbound]
      # puts(@settings[:inbound].class)

      next if @settings[:inbound] && !inscope?(current, scope)
      visited.push(current.to_s) # Add the URL to the visited list
      begin
        stamp = Time.now # Timestamp for the current request
        req = fetch(current) # Fetch the current URL
        stamp = Time.now - stamp # Calculate the time taken for the request (in seconds)

        next if req.nil?
        if req.body.nil?
          log(level: :warning, message: "#{current} returned an empty body. (#{req.code}) - #{stamp} seconds")
          next
        elsif !current.query.nil?
          begin
            next if tested.include?(normalize(current).to_s)

            heuristic(current, URI.decode_www_form(current.query))
            tested.push(normalize(current).to_s)
          rescue
            log(level: :error, message: "Unable to check heuristic for #{current} - #{current.query} : #{stamp} seconds")
          end
        end

        if req.is_a?(Net::HTTPRedirection) || req.is_a?(Net::HTTPMovedPermanently) || req.is_a?(Net::HTTPFound) || req.is_a?(Net::HTTPSeeOther) || req.is_a?(Net::HTTPTemporaryRedirect) || req.is_a?(Net::HTTPPermanentRedirect)
          if req["Location"].nil?
            log(level: :warning, message: "#{current} returned a redirection with no location. (#{req.code}) - #{stamp} seconds")
            next
          end
          pending.push(req["Location"])
          log(level: :httplog, message: "#{current} redirected to #{req["Location"]} [#{req.msg}] - #{stamp} seconds ", code: req.code)
          next
        end
        extracted = extractlinks(current, req.body)
        extracted.each do |page|
          next if page.nil? || page.empty?
          # puts page

          pending.push(page)
        end

        begin
          forms = req.body.scan(/<form.*?action=["'](.*?)["'].*?method=["'](.*?)["'].*?>(.*?)<\/form>/m)
          forms.each do |form|
            action = form[0]
            method = form[1].nil? || form[1].empty? ? "GET" : form[1].upcase
            inputs = req.body.scan(/<input.*?name=["'](.*?)["'].*?>/i).flatten
            if method == "GET"
              newUri = uri(action, current)
              next if newUri.nil? 
              hash = URI.decode_www_form(newUri.query || "") + inputs.map { |i| [i, ""] }
              newUri.query = URI.encode_www_form(hash.to_h)
              next if newUri.nil? || newUri.query.nil?
              next if visited.include?(normalize(newUri).to_s)
              visited.push(normalize(newUri).to_s)
              next if tested.include?(normalize(current).to_s)
              heuristic(newUri, URI.decode_www_form(newUri.query))
              tested.push(normalize(newUri).to_s)
            end
          end
        rescue => e
          log(level: :error, message: "Unable to check forms for #{current} : #{stamp} seconds \n#{e}\n#{e.backtrace.join("\n")}")
        end
        log(level: :httplog, message: "#{current.to_s} - #{req.msg} f(#{forms.size}) l(#{extracted.size}) - #{stamp} seconds", code: req.code)
      end
    end
    # On finish
    log(level: :info, message: "Thread ##{id} finished. Visited #{visited.size} pages in #{Time.now - startTimestamp} seconds.")
  end

  attr_reader :vulnerable, :visited, :settings, :ignoredexts, :UserAgents, :Agent
end

# def initialize(cookie: "", threads: 5, inbound: true, logreflection: false)
options = {
  "cookie" => "",
  "threads" => 5, # How many threads to use per target
  "inbound" => true,
  "logreflection" => false,
  "dork" => nil,
  "page" => 0,
  "url" => nil,
}

spider = Spider.new(cookie: options["cookie"], threads: options["threads"].to_i, inbound: options["inbound"], logreflection: options["logreflection"])

# spider.bot(1, "http://crawler-test.com/")
# spider.bot(2, "https://rawr.homes/waf?q=hi")

ARGV.each do |arg|
  next unless arg.start_with?("--") || arg.start_with?("-")
  k, v = arg.split("=", 2)
  k = k[2..]
  # puts options
  unless options.key?(k)
    puts("Invalid option: #{k}")
    exit 1
  end
  options[k] = v
end
ARGV.clear

if options["dork"].nil? && options["url"].nil?
  puts("Usage: #{__FILE__} --dork=<query>|--url=<url> [--cookie=<cookie>] [--threads=<threads>] [--inbound=<true/false>] [--logreflection=<true/false>] [--page=<page>]")
  puts("[--dork] - Google dork to search for : Especify page with --page=<page>")
  puts("[--url] - URL to scan")
  puts("[--cookie] - Cookie to use in requests")
  puts("[--threads] - Number of threads to use")
  puts("[--inbound] - Remain in the same domain")
  puts("[--logreflection] - Log reflection payloads")
  puts("[--page] - Page to start dorking")
  exit 1
end

spider = Spider.new(cookie: options["cookie"], threads: options["threads"].to_i, inbound: options["inbound"], logreflection: options["logreflection"])
targets = []
explored = []
threads = []

if options["dork"]
  spider.log(level: :info, message: "Using search results page ##{options["page"]}")
  results = spider.dork(options["dork"], options["page"].to_i + 1)
  if results.empty?
    spider.log(level: :error, message: "No results found for your search dork expression.")
    exit 1
  end
  # spider.log("found #{results.size} results for your search dork expression.")
  spider.log(level: :info, message: "Found #{results.size} results for your search dork expression.")
  targets.concat(results) # Add results to targets
elsif options["url"]
  targets << options["url"] # Add URL to targets
else
  spider.log(level: :error, message: "No target specified.")
  exit 1
end

targets.each_with_index do |target, index|
  next if target.nil? || target.empty?
  threads << Thread.new do
    spider.log(level: :info, message: "Starting thread ##{index} for #{target}")
    spider.bot(index, target)
  end
end

trap "SIGINT" do
  spider.log(level: :info, message: "Exiting...")
  # Before existing, log all the vulnerable pages
  spider.vulnerable.each do |vuln|
    spider.log(level: :info, message: "Vulnerable page: #{vuln[:url]} (#{vuln[:type]}) - #{vuln[:response]} - #{vuln[:param]}")
  end

  threads.each(&:exit)
  exit 0
end

threads.each(&:join)
