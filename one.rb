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
      inbound: inbound,
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

  def bot(id, url)
    localId = id
    localUrl = url
    hit = []
    pending = []
    pending.push(localUrl) # Add the first URL to the pending list
    while pending.any?
      target = pending.shift
      target = uri(target, localUrl)
      next if target.nil?
      next if hit.include?(normalize(target)) # Skip if already visited
      begin
        req = fetch(target)
        hit.push(normalize(target)) # Add the URL to the hit list (visited) # No need to normalize, we want the full URL here
        next if req.nil?

        # puts("Target: #{target} : Query: #{target.query}")
        if target.query
          # puts("Query: #{target.query}")
          heuristic(target, URI.decode_www_form(target.query))
          # Also add the url without the query to the pending list (this can be used to find more links)
          pending.push(uri(target, target.dup.query = nil))
        end

        if req.is_a?(Net::HTTPRedirection) || req.is_a?(Net::HTTPMovedPermanently) || req.is_a?(Net::HTTPFound) || req.is_a?(Net::HTTPSeeOther) || req.is_a?(Net::HTTPTemporaryRedirect) || req.is_a?(Net::HTTPPermanentRedirect)
          if req["Location"].nil?
            log(level: :httplog, message: "Broken redirection in: #{target} : #{req.code} (#{req.message})")
            return
          end
          pending.push(req["Location"]) # Add the redirection to the pending list
          log(level: :httplog, message: "#{target} ~> #{req["Location"]} #{req.message} ", code: req.code)
          next
        end
        bodysize = 0
        if !req.body.nil?
          bodysize = req.body.length

          begin
            forms = req.body.scan(/<form.*?action=["'](.*?)["'].*?method=["'](.*?)["'].*?>(.*?)<\/form>/m)
            forms.each do |form|
              action = form[0]
              method = form[1].nil? || form[1].empty? ? "GET" : form[1].upcase
              # Extract input elements
              inputs = req.body.scan(/<input.*?name=["'](.*?)["'].*?>/i).flatten
              # Update URI based on method
              form_uri = uri(action, target)
              if method == "GET"
                # Adjust the query string based on inputs' names
                query_hash = URI.decode_www_form(form_uri.query || "") + inputs.map { |i| [i, ""] }
                form_uri.query = URI.encode_www_form(query_hash)
              end
              next if form_uri.nil? || form_uri.query.nil?
              heuristic(form_uri, URI.decode_www_form(form_uri.query))
            rescue => e
              log(level: :error, message: "Error in bot: #{e}\n#{e.backtrace}")
            end
          end

          found = extractlinks(target, req.body)
          found.each do |link|
            next if link.nil? || link.empty? || link.start_with?("#")
            # Check it's inbounds
            if @settings[:inbound]
              begin
                next unless uri(link, target).host == target.host
              rescue => e
                # puts(">> Error: #{e} - #{link} - #{target} \n #{e.backtrace.join("\n")}")
              end
            end
            # puts link
            pending.push(link)
          end
        end

        log(level: :httplog, message: "#{target} - #{req.message} - B(#{bodysize})", code: req.code)
      rescue => e
        log(level: :error, message: "Error in bot: #{e}\n#{e.backtrace}")
      end
    end
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
    puts options

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
    spider.bot(index, target)
  end
end

trap "SIGINT" do
  spider.log(level: :info, message: "Exiting...")
  # Before existing, log all the vulnerable pages
  spider.vulnerable.each do |vuln|
    spider.log(level: :error, message: "Vulnerable page: #{vuln[:url]} (#{vuln[:type]}) - #{vuln[:response]} - #{vuln[:param]}")
  end

  threads.each(&:exit)
  exit 0
end

threads.each(&:join)

# while targets.any?
#   # Depending how many threads are active, we can add more targets.
#   if threads.size < spider.settings[:threads]
#     target = targets.shift
#     next if explored.include?(target) # Skip if already explored
#     explored << target
#     uri = spider.uri(target)
#     next if uri.nil? # Skip invalid URL's
#     threads << Thread.new do
#       begin
#         req = spider.fetch(uri)
#         next if req.nil?
#         spider.heuristic(uri, URI.decode_www_form(uri.query)) if spider.settings[:inbound]
#         spider.extractform(uri, req.body).each do |form|
#           next if form.nil?
#           spider.heuristic(form, URI.decode_www_form(form.query)) if spider.settings[:inbound]
#         end
#         spider.extractlinks(uri, req.body).each do |link|
#           next if link.nil?
#           targets << link
#         end
#       rescue => e
#         spider.log(level: :error, message: "Error in thread: #{e}\n#{e.backtrace}")
#       end
#     end
#   end
# end

# # while targets.any?
# #   target = targets.shift
# #   puts target
# #   uri = spider.uri(target)
# #   next if uri.nil? # Skip invalid URL's

# #   begin
# #     req = spider.fetch(uri)
# #     next if req.nil?
# #     # puts spider.extractlinks(uri, req.body)

# #     if spider.settings[:inbound]

# #     # spider.log(level: :httplog, message: "#{normalised} -> #{spider.color(req.code)}")
# #     # spider.heuristic(normalised, URI.decode_www_form(normalised.query)) if normalised.query

# #   end
# # end

# usage: ruby one.rb --dork="inurl:php?id=" --page=0 --threads=5 --inbound=true --logreflection=false
