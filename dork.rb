require("net/http")
require("uri")
require("cgi")

# "CONSENT=YES+shp.gws-%s-0-RC1.%s+FX+740" % (time.strftime("%Y%m%d"), "".join(random.sample(string.ascii_lowercase, 2)))
def generateConsent
  time = Time.new
  return "CONSENT=YES+shp.gws-#{time.strftime("%Y%m%d")}-0-RC1.#{SecureRandom.alphanumeric(2).downcase}+FX+740"
end

RequestHeaders = {}
responseHeaders = {}
RequestHeaders["User-Agent"] = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"
RequestHeaders["Cookie"] = generateConsent

def request(url, headers = RequestHeaders)
  uri = URI.parse(url)
  req = Net::HTTP::Get.new(uri)
  headers.each do |key, value|
    req[key] = value
  end
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == "https"
  # Disable SSL verification
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  response = http.request(req)
  return response
end

dork = ARGV[0]

uri = "https://www.google.com/search?"
uri += "q=#{URI.encode_uri_component(dork)}"
uri += "&num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search&start=0" # Start at 1

def escapeHex(string)
  return string.gsub(/\\x([0-9A-Fa-f]{2})/) { |match| $1.hex.chr }
end

def to_unicode(value, encoding = "UTF-8")
  raise if value.nil?

  case value
  when String
    return value # If already a string, return as is
  when Array
    return value.map { |v| to_unicode(v, encoding) } # Recursively handle arrays
  else
    begin
      return value.to_s.encode("UTF-8") # Convert other types to UTF-8 string
    rescue Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError
      return value.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "?")
    end
  end
end

begin
  response = request(uri)
  puts("Requesting: #{uri}")
  puts("Response: #{response.code}")
  puts("Response Headers: #{response.to_hash}")
  page = response.body


  if page.include?("Our systems have detected unusual traffic")
    puts("Google has flagged this IP. Please repeat the search on your browser and complete the CAPTCHA.")
    puts("Then wait for a few minutes before trying again.")
    exit
  end
  regex = /href="\/url\?esrc=s&q=&rct=j&sa=U&url=([^&]+)&ved=[^"]+" data-ved="[^"]+"/
  # page = File.read("results.html")



  # Decode the page
  page = escapeHex(page)
  page = CGI.unescapeHTML(page)
  page.gsub!(/<script.*?>.*?<\/script>/m, "")
  page.gsub!(/<style.*?>.*?<\/style>/m, "")
  # page.gsub!(/<.*?>/, "")
  page.gsub!(/&nbsp;/, " ")
  page.gsub!(/&amp;/, "&")
  
  

  found = page.scan(regex).map do |match|
    decoded_url = match[0] || match[1]
  end
  puts found

rescue Exception => e
  puts("#{e} : #{e.backtrace}")
  puts("Failed to connect to Google. Check your internet connection.")
end
