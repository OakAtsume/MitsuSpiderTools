require('securerandom')
require('net/http')
require('uri')
require('cgi')

class SnowBlood
  def initialize(settings = {})
    # Stuff for logo n colors #
    @logo = [
      '                                      ██████        ',
      '█               █                   ███████████     ',
      '██             ██                  ███     █████    ',
      '███          ████                  ███ █     █████  ',
      '████ ██████ █████                  ████      ████   ',
      '█████████████████    ██████████                ████ ',
      '███████████████████████████████████            ████ ',
      '████  ████  █████████████████████████          ████ ',
      '████  ████  ███████████████████████████       █████ ',
      '████  ████  ██████████████████████████████████████  ',
      ' ████████████████████████████████████████████████   ',
      '   ███████████████████████████████████ ████████     ',
      '           ████████████████████████████             ',
      '          █████████████   █████████████             ',
      '         ██████ ███████    █████████████            ',
      '       ████████  ██████     ██████ ████████         ',
      '     █████████    ██████     ███████ ██████         ',
      '   ██████         ██████       █████   ████         ',
      '  █████          ████          ████     ████        ',
      '  █████         ████          ████      ████        ',
      '  ████     █████████      ███████    ████████       ',
      '   ██      ███████       ███████     ███████        '
    ]
    # The Tism's kicked in and now it's full compact
    @color = {
      green: "\e[32m",
      red: "\e[31m",
      yellow: "\e[33m",
      blue: "\e[34m",
      cyan: "\e[36m",
      bold: "\e[1m",
      end: "\e[0m",
      reset: "\e[0m"
    }
    @excludeExt = %w[
      png
      jpg
      jpeg
      gif
      ico
      svg
      css
      js
      pdf
      zip
      rar
      tar
      gz
      7z
      mp3
      mp4
      wav
      avi
      mkv
      wmv
      mov
      flv
      pdf
      doc
      docx
      xls
      xlsx
      ppt
      pptx
    ]

    # Default stuff #

    @settings = settings

    # Correct settings values

    # "true" to true (boolean)
    # "false" to false (boolean)
    @settings.each do |key, value|
      if value == 'true'
        @settings[key] = true
      elsif value == 'false'
        @settings[key] = false
      end
    end

    @useragent = if @settings.key?('agent') && !@settings['agent'].empty?
                   @settings['agent']
                 else
                   [
                     'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
                     'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
                     'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; TheWorld)',
                     'Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+',
                     'Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; zh-TW) AppleWebKiwt/534.8+ (KHTML, like Gecko) Version/6.0.0.448 Mobile Safari/534.8+'
                   ].sample
                 end
    @vulns = []
    @queries = [] # URL's with queries

    unless @settings['savevulns'].empty?
      log(level: :info, message: "Saving vulnerable URL's to: #{@settings['savevulns']}")
    end

    return if @settings['savequeries'].empty?

    log(level: :info, message: "Saving found queries to: #{@settings['savequeries']}")
  end

  attr_reader :color, :vulns

  def log(level: :info, message: '', msg: '', code: nil)
    timestamp = Time.now.strftime('%H:%M:%S')
    case level
    when :info
      puts("[\e[36m#{timestamp}\e[0m] [\e[32mINFO\e[0m] #{message}")
    when :error
      puts("[\e[36m#{timestamp}\e[0m] [\e[31mERROR\e[0m] #{message}")
    when :httplog
      puts("[\e[36m#{timestamp}\e[0m] [\e[34mHTTP\e[0m] (#{httpcolor(code)}) #{msg} | #{message} ")
    when :heuristicXSS
      puts("[\e[36m#{timestamp}\e[0m] [\e[31mXSS\e[0m] #{message}")
    when :heuristicSQLi
      puts("[\e[36m#{timestamp}\e[0m] [\e[31mSQLi\e[0m] #{message}")
    when :heuristicRedirect
      puts("[\e[36m#{timestamp}\e[0m] [\e[31mRedirect\e[0m] #{message}")
    when :heuristicLFI
      puts("[\e[36m#{timestamp}\e[0m] [\e[31mLFI\e[0m] #{message}")
    when :warning
      puts("[\e[36m#{timestamp}\e[0m] [\e[33mWARNING\e[0m] #{message}")
    else
      puts("[\e[36m#{timestamp}\e[0m] [\e[34mDEBUG\e[0m] #{message}")
    end
  end

  def httpcolor(code)
    case code
    when '200'
      "\e[32m#{code}\e[0m" # Green for OK
    when '301', '302', '303', '307', '308'
      "\e[34m#{code}\e[0m" # Blue for Redirection
    when '400', '401', '403', '404', '405', '406'
      "\e[33m#{code}\e[0m" # Yellow for Client Errors
    when '500', '501', '502', '503', '504', '505'
      "\e[31m#{code}\e[0m" # Red for Server Errors
    else
      code # No color for other codes
    end
  end

  def randColor
    r = rand(0..255)
    g = rand(0..255)
    b = rand(0..255)
    "\e[38;2;#{r};#{g};#{b}m"
  end

  def urihandle(path, base = nil)
    # Encode the path (To deal with special characters)
    # path = URI.encode_uri_component(path)
    # iF path has special characters, it will be encoded
    # if !path.ascii_only?
    # Handle special characters, and spaces
    # For any special charater, encode and replace
    # path = path.gsub(/[^a-zA-Z0-9_\-.:\/~?&=]/) { |char| URI.encode_uri_component(char) }

    # Encode non-ascii charaters excluding common web charaters
    exclude = [
      '/',
      '@',
      '?',
      '=',
      ':',
      '.',
      '~',
      '&',
      '-',
      '_',
      '%',
      '+',
      '#',
      '!',
      '$',
      ',',
      ';'

    ]
    path.gsub!(%r{[^a-zA-Z0-9_\-.:/~?&=]}) { |char| exclude.include?(char) ? char : URI.encode_uri_component(char) }

    # end
    if /^http/.match?(path)
      URI.parse(path)
    elsif %r{^//}.match?(path)
      URI.join(base, path)
    elsif path.include?('#')
      split = path.split('#')[0]
      URI.parse(path.split('#')[0]) unless split.nil?
    else
      begin
        URI.join(base, path)
      rescue StandardError
        # puts("1-Error: #{e} - #{path} \n #{e.backtrace}")

        nil
      end
    end
  rescue StandardError
    # puts("2-Error: #{e} - #{path} \n #{e.backtrace}")
    nil
  end

  def normalize(uri)
    nil if uri.nil?
    # uri = uri.dup
    uri.fragment = nil
    if uri.query
      # parse and turn query into an hash {key: value}
      val = URI.decode_www_form(uri.query).to_h
      val.each do |k, _v|
        val[k] = ''
      end
      # Re-encode the query
      uri.query = URI.encode_www_form(val)
    end

    # puts "Normal: #{uri}"
    uri
  end

  def renderLogo
    @logo.each do |line|
      puts("#{randColor}#{line}\e[0m")
    end
    puts("\tSnowBlood - Private-Full")
    puts("\t - By: @OakAtsume")
    puts("\t Heavily inspired by: SQLMap")
  end

  # Requester #
  def fetch(uri, headers: {}, parameters: {}, agent: @useragent)
    request = Net::HTTP::Get.new(uri)
    request['User-Agent'] = agent
    request['Cookie'] = @settings[:cookie] if @settings.key?(:cookie)
    headers.each do |key, value|
      request[key] = value
    end
    request.set_form_data(parameters) if parameters.any?
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                        verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      http.request(request)
    end
  rescue StandardError => e
    log(level: :error, message: "Error fetching URL: #{uri}\n#{e}\n#{e.backtrace}")
    nil
  end

  def dork(query, page = 0)
    cookie = "CONSENT=YES+shp.gws-#{Time.new.strftime('%Y%m%d')}-0-RC1.#{SecureRandom.alphanumeric(2).downcase}+FX+740"
    uri = "https://www.google.com/search?q=#{URI.encode_uri_component(query)}&num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search&start=#{page}"
    uri = URI.parse(uri)
    req = fetch(uri, headers: { 'Cookie' => cookie },
                     agent: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0')
    puts req.inspect
    if req.nil? || req.body.nil?
      log(level: :error, message: "Error in dork: #{query}")
      return []
    end

    if req.body.include?('Our systems have detected unusual traffic')
      log(level: :error, message: 'Google has detected unusual traffic, please try again later.')
      exit 1
    end
    page = req.body
    page = page.gsub(/\\x([0-9A-Fa-f]{2})/) { |_match| ::Regexp.last_match(1).hex.chr }
    page = CGI.unescapeHTML(page)
    page.gsub!(%r{<script.*?>.*?</script>}m, '')
    page.gsub!(%r{<style.*?>.*?</style>}m, '')
    page.gsub!('&nbsp;', ' ')
    page.gsub!('&amp;', '&')
    found = page.scan(%r{href="/url\?esrc=s&q=&rct=j&sa=U&url=([^&]+)&ved=[^"]+" data-ved="[^"]+"}).flatten
    # Turn found into an array and return only unique values
    found = found.uniq
    # From Found, decode all the URL's
    # Aka turn https://example.com/%3Fparam=value into https://example.com/?param=value
    puts found
    newlist = []
    found.each do |url|
      url = URI.decode_uri_component(url)
      newlist.push(url)
    end
    newlist
  rescue StandardError => e
    log(level: :error, message: "Error in dork: #{query}\n#{e}\n#{e.backtrace}")
    []
  end

  def extract(body, base)
    # Extracts all links and forms from page
    # Forms are formatted into URLs with parameters (if GET)
    links = []
    urls = body.scan(/href="([^"]+)"/).flatten.uniq.map { |url| url.gsub('&amp;', '&') }
    urls.each do |url|
      # if url.start_with?("/")
      #   begin

      #   rescue => e
      #     puts("Error: #{e} - #{url} \n #{e.backtrace.join("\n")}")
      #     next
      #   end
      # end

      uri = urihandle(url, base)
      next if uri.nil?

      # Check for inbound
      next if @settings['inbound'] && !base.host == (uri.host)

      links << uri
      # From here, we check extensions and remove them
      # If the extension is in the exclude list
      links = links.reject do |link|
        ext = link.path.split('.').last
        next false if ext == link.path # No extension

        @excludeExt.include?(ext)
      end
    rescue URI::InvalidURIError
      puts("Invalid URI: #{url}")
      next
    end

    forms = body.scan(%r{<form.*?>.*?</form>}m).flatten

    forms.each do |form|
      # Check for method GET/get
      method = form.match(/method=["']?([^"'>]+)/i)
      next if method.nil?
      next unless method[1].downcase == 'get'

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
        value = value.nil? ? '' : value[1]
        params[name] = value
      end
      # puts("Form specs: #{action} - #{params}")
      # uri = URI.parse(action)
      # Turn results into a URL
      # Such as: http://example.com/?param=value
      url = "#{action}?#{URI.encode_www_form(params)}"
      formURI = urihandle(url, base)

      next if formURI.nil?

      # Check for inbound
      if @settings['inbound'] && !base.host == (formURI.host)
        # puts ("#{base.host} - #{uri.host}")
        next
      end

      links << formURI
    rescue URI::InvalidURIError
      puts("Invalid URI: #{action}")
      next
    end
    # puts("Crawl: #{links}")
    links
  end

  def crawl(uri)
    pages = []
    visited = [] # Array of threads
    bound = uri.dup
    pages.push(uri)

    # # First hit
    # req = fetch(uri)
    # return if req.nil?
    # return if req.body.nil?

    # found = extract(req.body, uri)
    # found.each do |link|
    #   pages.push(link)
    # end

    # Loop through all pages
    while pages.any?
      page = pages.pop
      next if visited.include?(page) || visited.include?(normalize(page))

      visited.push(normalize(page))
      req = fetch(page)
      # puts req
      next if req.nil?

      if req.body.nil?
        log(level: :warning, message: "#{page} returned an empty body (#{req.code})")
        next
      elsif !page.query.nil?
        # Check heuristics
        @queries.push(page.to_s)
        File.open(@settings['savequeries'], 'a') { |f| f.write("#{page}\n") } unless @settings['savequeries'].empty?
        heuristic(page, URI.decode_www_form(page.query).to_h)
      end

      if req.is_a?(Net::HTTPRedirection) || req.is_a?(Net::HTTPMovedPermanently) || req.is_a?(Net::HTTPFound) || req.is_a?(Net::HTTPSeeOther) || req.is_a?(Net::HTTPTemporaryRedirect) || req.is_a?(Net::HTTPPermanentRedirect)
        if req['Location'].nil?
          log(level: :warning, message: "#{page} returned a redirection without a location header")
          next
        end
        location = urihandle(req['Location'], page)
        next if location.nil?

        if @settings['inbound'] && !location.host == (page.host)
          # puts ("#{location.host} - #{page.host}")
          next
        end

        pages.push(location)
      end

      if @settings['inbound']
        next unless uri.host == page.host

        # puts ("#{uri.host} - #{page.host}")

        extract(req.body, bound).each do |link|
          next if pages.include?(link)
          next if visited.include?(link)

          pages.push(link)
        end
      else
        extract(req.body, page).each do |link|
          next if pages.include?(link)
          next if visited.include?(link)

          pages.push(link)
        end
      end

      # [Time] [HTTP] [ url ] - [Msg] f(x) l(x) - <time> seconds : (code)
      log(level: :httplog, message: "#{page} f(#{pages.length}) l(#{visited.length})", code: req.code,
          msg: "#{req.msg}")
      # log(level: :httplog, message: page, msg: "f(#{pages.length}) l(#{visited.length})", code: req.code)
    end
    # All pages have been visited
  end

  def heuristic(uri, params)
    params.each do |param|
      # Do the first check, this just sends a simple random hex number, if reflected we test XSS and look for LFI errors
      testuri = uri.dup
      payload = SecureRandom.hex(8)
      testuri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, payload] : [k, v] })
      req = fetch(testuri)
      if req.nil? || req.body.nil?
        log(level: :error, message: "Error in heuristic: #{uri} : Returned no body")
        next
      end
      if req.body.include?(payload)
        # log(level: :reflections, message: "#{uri} : Reflection in #{param[0]}")
        if @settings['xss']
          # Check XSS
          testuri = uri.dup
          payload = "#{SecureRandom.hex(8)}<'\">#{SecureRandom.hex(8)}"
          testuri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, payload] : [k, v] })
          req = fetch(testuri)
          if req.nil? || req.body.nil?
            log(level: :error, message: "Error in heuristic: #{uri} : Returned no body")
            next
          end
          if req.body.include?(payload)
            log(level: :heuristicXSS, message: "#{uri} : XSS in #{param[0]}")
            @vulns.push({ url: uri, type: 'XSS', payload: payload, response: "Reflection Of Payload Vector (<'\">)",
                          param: param[0] })
            unless @settings['savevulns'].empty?
              File.open(@settings['savevulns'], 'a') do |f|
                f.write("#{uri} # XSS : #{param[0]} : Reflection Of Payload Vector (<'\">)\n")
              end
            end
          end
        end
        if @settings['lfi'] && req.body.match?(/(?i)[^\n]{0,100}(no such file|failed (to )?open)[^\n]{0,100}/)
          log(level: :heuristicLFI,
              message: "LFI found in: #{uri} (#{param[0]}) - Reflection Of Payload Vector (no such file)")
          @vulns.push({ url: uri, type: 'LFI', payload: '', response: 'Reflection Of Payload Vector (no such file)',
                        param: param[0] })
          # @vulnerable << { url: uri, type: "LFI", payload: "", response: "Reflection Of Payload Vector (no such file)", param: param[0] }
          unless @settings['savevulns'].empty?
            File.open(@settings['savevulns'], 'a') do |f|
              f.write("#{uri} # #{param[0]}  Reflection Of Payload Vector (<'\">)\n")
            end
          end
        end
      end

      # Check for SQLi
      next unless @settings['sqli']

      payloads = [
        "'",
        '"',
        "')",
        '"))',
        "';",
        '";',
        "';--",
        '";--',
        "';#"
      ]
      flags = [
        /SQL syntax/i,
        /SQL error/i,
        /SQL query/i,
        /SQLSTATE/i,
        /You have an error in your SQL syntax/i,
        /Warning: mysql_query/i,
        /Warning: pg_query/i,
        /Warning: oci_parse/i

      ]
      payloads.each do |payload|
        testuri = uri.dup
        testuri.query = URI.encode_www_form(params.map { |k, v| k == param[0] ? [k, "#{v}#{payload}"] : [k, v] })
        req = fetch(testuri)
        if req.nil? || req.body.nil?
          log(level: :error, message: "Error in heuristic: #{uri} : Returned no body")
          next
        end
        next unless flags.any? { |flag| req.body.match?(flag) }

        flag = flags.select { |flag| req.body.match?(flag) }
        log(level: :heuristicSQLi,
            message: "SQLi found in: #{uri} (#{param[0]}) Payload: (#{payload}) Flag: #{flag}")
        @vulns.push({ url: uri, type: 'SQLi', payload: payload, response: "Payload: (#{payload}) Flag: #{flag}",
                      param: param[0] })
        unless @settings['savevulns'].empty?
          File.open(@settings['savevulns'], 'a') do |f|
            f.write("#{uri} # SQLi : #{param[0]} : Reflection Of Payload Vector (#{payload})\n")
          end
        end
        # If found break the loop
        break
      end
    end
  rescue StandardError => e
    log(level: :error, message: "Error in heuristic: #{uri}\n#{e}\n#{e.backtrace}")
  end
end

settings = {
  # Settings for the bot's themselves
  'threads' => 10, # Maximum number of bots running at the same time
  'threadper' => 10, # Maximum number of sub-crawlers per bot
  'inbound' => true, # Remain inboud of the bot's original domain
  # Settings for the targets
  'url' => nil, # Url of a single target
  'dork' => nil, # Dork to search for
  'file' => nil, # File with a list of targets
  # Options for targets
  'page' => 1, # Page to start from (for dorking)
  # Settings for vulnerability checks
  'reflections' => true, # Log any Reflections
  'xss' => true, # Log any XSS
  'lfi' => true, # Log any LFI
  'sqli' => true, # Log any SQLi
  'redirect' => true, # Log any Potential Open Redirects # PoC
  # Other stuff
  'agent' => '', # User-Agent to use (Custom)
  'respectdelay' => true, # Respect delay's such as "Too many requests"
  'delay' => 4, # Delay between requests (in seconds)
  'savequeries' => '', # File to write all found queries : URL?param=value (for further testing)
  'savevulns' => '' # File to write all found vulns : URL : Type : Param : Response
}

ARGV.each do |arg|
  next unless arg.start_with?('--', '-')

  k, v = arg.split('=', 2)
  k = k[2..-1]

  if k == 'help'
    # mitsu.log(level: :info, message: "Help Menu")
    settings.each do |key, value|
      # puts("\t--#{key}=#{log.color[:bold]}#{value}#{log.color[:end]} : #{log.color[:cyan]}#{value.class}#{log.color[:end]}")
      # mitsu.log(level: :info, message: "\t--#{key}=#{mitsu.color[:bold]}#{value}#{mitsu.color[:end]} : #{mitsu.color[:cyan]}#{value.class}#{mitsu.color[:end]}")
      puts("\t--#{key}=#{value}")
    end
    exit(0)
  end

  unless settings.key?(k)
    # puts("Invalid argument: #{log.color[:bold]}#{k}#{log.color[:reset]} -> #{log.color[:bold]}#{v}#{log.color[:end]}")
    # puts ("Invalid argument: #{mitsu.color[:bold]}#{k}#{mitsu.color[:end]} -> #{mitsu.color[:bold]}#{v}#{mitsu.color[:end]}")
    puts("Invalid argument: #{k} -> #{v}")
    # log.log(level: :error, message: "Invalid argument: #{log.color[:bold]}#{k}#{log.color[:end]} -> #{log.color[:bold]}#{v}#{log.color[:end]}")
    next
  end

  settings[k] = v
end

mitsu = SnowBlood.new(settings)
mitsu.renderLogo

globaltargets = []

if !settings['url'].nil?
  # puts settings["url"]
  globaltargets.push(settings['url'])
elsif !settings['dork'].nil?
  dork = mitsu.dork(settings['dork'], settings['page'])

  globaltargets = dork
elsif !settings['file'].nil?
  File.open(settings['file'], 'r').each do |line|
    globaltargets.push(line.strip)
  end
else
  mitsu.log(level: :error, message: 'No targets specified')
  exit(1)
end

# Post processing of the targets
# This will remove duplicates and invalid URI's
globaltargets.uniq! # Returns an array with all duplicates removed

# puts globaltargets
newset = []
globaltargets.each do |target|
  uri = mitsu.urihandle(target)
  next if uri.host.nil?

  newset.push(uri)
rescue URI::InvalidURIError
  puts("Invalid URI: #{target}")
  next
end
globaltargets = newset

mitsu.log(level: :info, message: "Loaded #{newset.length} sites to crawl")

bots = []

# On Control-C or Exit / kill
Signal.trap('INT') do
  puts("\nExiting...")
  bots.each do |bot|
    bot.kill
  end
  # Log all vulns
  mitsu.vulns.each do |vuln|
    puts("#{vuln[:url]} : #{vuln[:type]} : #{vuln[:param]} : #{vuln[:response]}")
  end
  exit(0)
end

# ON Control-C
Signal.trap('TERM') do
  puts("\nExiting...")
  bots.each do |bot|
    bot.kill
  end
  # Log all vulns
  mitsu.vulns.each do |vuln|
    puts("#{vuln[:url]} : #{vuln[:type]} : #{vuln[:param]} : #{vuln[:response]}")
  end
  exit(0)
end

# Considering how many bot can be run at the same time

newset.each do |target|
  if bots.length >= settings['threads']
    # Wait for a bot to finish
    bots.each do |bot|
      bot.join
    end

    bots = []
  end
  # Create a new bot
  bot = Thread.new do
    mitsu.crawl(target)
  end
  bots.push(bot)
end

loop do
  sleep(1)
end
