#Labels {'user', 'domain', 'src_ip', 'dst_ip', 'mac', 'src_net', 'dst_net', 'src_port', 'dst_port'}
require 'time'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'

def register(params)
    $stdout.sync = true
    @mc = Dalli::Client.new('memcached.memcached.svc.cluster.local:11211')
    @record_def = load_fields_map('/configs/fields-map.cfg')
    @fields_pattern = load_fields_pattern('/configs/pattern-map.cfg')
end

def get_not_empty(old_value, new_value)
    if (new_value == "")
        return old_value
    end

    return new_value
end

def load_fields_map(file_name)
    rec_map = Hash.new()
    fo = File.new(file_name, "r")
  
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        tokens = line.split(":")
        cnt = 0
        rectype = ''
        fields_map = nil
  
        tokens.each do |token|
            if (cnt == 0)
                rectype = token
                rec_map[rectype] = Hash.new(rectype)
                fields_map = rec_map[rectype]
            else
                field_name, index = token.split("=")
                fields_map[field_name] = index.strip
                puts("DEBUG : #{rectype}:#{field_name}->#{index}")
            end
            cnt = cnt+1
        end
    end
    fo.close
  
    return rec_map
end

def load_fields_pattern(file_name)
    rec_map = Hash.new()
    fo = File.new(file_name, "r")
  
    while (line = fo.gets)
        #comment line
        if line.match(/^#.*$/)
            next
        end
  
        #blank line
        if line.match(/^\s*$/)
            next
        end
  
        rectype, pattern = line.split('|')        
        rec_map[rectype] = pattern.strip

        puts("DEBUG2 : #{rectype}->#{pattern.strip}")
    end
    fo.close

    return rec_map
end

def update_user_properties(event, src_ip)
    key = "ip-properties-map:#{src_ip}"
    obj = {}

    ip_prop = @mc.get(key)
    if ip_prop
        obj = JSON.parse(ip_prop)
        user = get_not_empty("==unknown==", obj['user'])

        event.set('possible_user', user)
        #puts "### [DEBUG] Updated field [possible_user] value [#{user}], for ip=[#{src_ip}]"
    end
end

def update_src_ip_cache(src_ip, mac, user)
    key = "ip-properties-map:#{src_ip}"

    obj = {}
    ip_prop = @mc.get(key)
    if ip_prop
        #Found - Do nothing
        #puts "### [Found] Getting IP property from cached [#{key}] value [#{src_ip}]"

        obj = JSON.parse(ip_prop)
        obj['mac'] = get_not_empty(obj['mac'], mac)
        obj['user'] = get_not_empty(obj['user'], user)
    else
        #puts "### [Notfound] Getting IP property from cached [#{key}] value [#{src_ip}]"
        obj = {
            "mac" => mac,
            "user" => user
        };
    end
    
    json_str = obj.to_json
    @mc.set(key, json_str) #No expire
    #puts "### [DEBUG] cache [#{key}] value [#{json_str}]"
end

def extract_hotspot(event, message, category)
    #hotspot,account,info,debug 0-Napbiotec: seubpong.mon (192.168.20.29): logged in
    groups = message.scan(/^.*:\s(.+?)\s\((.+?)\):.+$/i)[0]
    user = groups[0]
    src_ip = groups[1]

    event.set('user', user.strip)
    event.set('possible_user', user.strip)
    event.set('src_ip', src_ip.strip)
    event.set('debug_field1', category)

    if ((message.include? "logged in") || 
        (message.include? "logged out"))
        update_src_ip_cache(src_ip, '', user)
    end     
end

def extract_firewall(event, message, category)
    #   0                1          2            3               4           5             6           7    8        9                          10                    11                
    # firewall,info 0-Napbiotec: forward: in:vlan20-office out:pppoe-tot, src-mac b4:0f:b3:1d:63:4b, proto TCP (ACK,FIN,PSH), 192.168.20.171:43996->47.241.18.42:443, NAT (192.168.20.171:43996->125.25.69.110:43996)->47.241.18.42:443, len 71
    if message.include? "NAT"
        groups = message.scan(/^.*?in:(.+?)\s+out:(.+?),\s*src-mac\s+(.+?),.*,\s*(.+?):(.+?)->(.+?):(.+?),\sNAT\s(.*)$/i)[0]
    else
        groups = message.scan(/^.*?in:(.+?)\s+out:(.+?),\s*src-mac\s+(.+?),.*,\s*(.+?):(.+?)->(.+?):(.+?),\slen\s(.*)$/i)[0]
    end
    src_net = groups[0]
    dst_net = groups[1]
    mac = groups[2]
    src_ip = groups[3]
    src_port = groups[4]
    dst_ip = groups[5]
    dst_port = groups[6]

    event.set('src_net', src_net.strip)
    event.set('dst_net', dst_net.strip)
    event.set('mac', mac.strip)
    event.set('src_ip', src_ip.strip)
    event.set('src_port', src_port.strip)
    event.set('dst_ip', dst_ip.strip)
    event.set('dst_port', dst_port.strip)
    event.set('debug_field1', category)

    update_user_properties(event, src_ip.strip)
end

def extract_webproxy(event, data, category)
    #   0         1              2        3                  4                            5
    #account 0-Napbiotec: 192.168.20.115 GET http://cu.bwc.brother.com/certset/ver  action=allow cache=MISS        
    arr2 = data.split(' ')
    src_ip = arr2[2]
    url = arr2[4]

    event.set('src_ip', src_ip.strip)
    event.set('domain', URI.parse(url).host)
    event.set('debug_field1', category)
    update_user_properties(event, src_ip.strip)
end

def extract_dhcp(event, data, category)
    # 0        1         2      3           4         5       6   
    #info 0-Napbiotec: dhcp6 assigned 192.168.30.236 to E2:9B:9D:A9:DF:5B
    arr2 = data.split(' ')
    src_ip = arr2[4]
    mac = arr2[6]
    state = arr2[3].strip

    event.set('src_ip', src_ip.strip)
    event.set('mac', mac)
    event.set('debug_field1', category)

    if (state == "assigned")
        update_src_ip_cache(src_ip, mac, '')
    end
end

def extract_dns(event, message, category)
    #dns 0-Napbiotec: query from 170.81.19.85: #16897106 peacecorps.gov. ALL
    event.set('debug_field1', "unknown")

    if match = message.match(/^dns.+query from (.+?): .+ (.+)\..*$/i)
        src_ip, domain = match.captures

        event.set('src_ip', src_ip.strip)
        event.set('domain', domain)
        event.set('debug_field1', category)
        update_user_properties(event, src_ip.strip)
    end
end

def populate_event_category(event)
    category = "undefined"
    message = event.get('message')

    tokens = nil
    @fields_pattern.each do |key, pattern|
        if m = message.match(/#{pattern}/)
            tokens = m.captures
            category = key

            #puts "### [Match] [#{key}] [#{message}], [#{pattern}]"
            break
        else
            #puts "### [Not Match] [#{key}] [#{message}], [#{pattern}]"
        end
    end

    event.set('evt_category', category)
    return tokens
end

def parse_fields(event, tokens)
    category = event.get('evt_category')    
    fields_map = @record_def[category]

    if !fields_map.nil?
        fields_map.each do |field, index|
            idx = index.to_i - 1 # zero base index
            value = tokens[idx]
            if !value.nil?
                event.set(field, value)
            else
                #puts("Error - Field index [#{idx}], delimit by [#{delimit}] not found in category [#{category}]")
                event.set('evt_debug', "Index not found field=[#{field}] idx=[#{index}]")
            end
        end
    else
        #puts("Error - Category [#{category}] not found in fields-map.cfg")
        event.set('evt_debug', "Unable to map fields [#{category}]")
    end
end

def generate_fields(event)
    fields = []
    event.to_hash.each do |key, value|
        if key.match(/^evt_.*$/)
            fields.push(key)
        end
    end

    sorted_fields = fields.sort
    return sorted_fields
end

def create_metric(event)
    payload = event.get('genuine_payload')
    category = event.get('evt_category')
    category_org = event.get('evt_category_org')

    if payload.nil? or payload == ''
        obj = Hash.new()
    else
        obj = JSON.parse(payload)
    end 

    sorted_fields = generate_fields(event)
    sorted_fields.each do |field|
        value = event.get(field).to_s
        obj[field] = value.strip
    end
    
    obj["id"] = SecureRandom.uuid
    obj["pod_name_syslog"] = ENV["POD_NAME"]

    if category.nil? or category == '' or category == 'undefined'
        obj["evt_category"] = category_org
    end

    event.set("metrics", obj)
end

def populate_ts_aggregate(event)
    dtm = DateTime.now
    dtm += Rational('7/24') # Thailand timezone +7

    event.set('evt_ts_yyyy', dtm.year)
    event.set('evt_ts_mm', dtm.mon.to_s.rjust(2,'0'))
    event.set('evt_ts_dd', dtm.mday.to_s.rjust(2,'0'))
    event.set('evt_ts_hh', dtm.hour.to_s.rjust(2,'0'))
end

def get_category(event, message)
    category = "undefined"

    if match = message.match(/^.+? .+? genuine-(.+?)-.+?-.+? dotnet (.+?) - - (.*)$/)
        puts("DEBUG --> #{message}")

        env, version, payload = match.captures
        category = "genuine-#{env}"
        event.set('genuine_payload', payload)
    elsif message.include? "Omada Controller"
        category = "omda-controller"
    else
        arr1 = message.split(',')
        category = arr1[0]
    end

    if category.length > 20
        sub_cat = category[0, 4]
        category = "unknown"

        if sub_cat == "dns " #Need a space at the end
            #dns 0-Napbiotec: done query: #16768652 dns name exists, but no appropriate record
            category = "dns"
        end
    end

    return category
end

def get_misp_response(attribute, value)
    # Not use for now due to rate limit
    return nil

    uri = URI.parse('https://misppriv.circl.lu/attributes/restSearch')
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true
    api_key = ENV["MISP_API_KEY"]

    request = Net::HTTP::Post.new(uri.path)
    request['Accept'] = 'application/json'
    request['Content-Type'] = 'application/json'
    request['Authorization'] = api_key

    data = {
        "returnFormat" => "json",
        "enforceWarninglist" => true,
        "value" => value,
        "limit" => "1",
        "type" => { "OR" => [ attribute ] }
    }.to_json;
    request.body = "#{data}"

    response = https.request(request)
    if (response.code == "200")
        #puts response.body

        return response.body
    end

    puts "### [Error] MISP returned [#{response}]"
    return nil
end

def load_cti_cahce(event, cache, value_field, attribute, label)
    value = event.get(value_field)

    if value.nil? or value == ''
        #puts "Nothing to do because the field [#{value_field}] is blank [#{value}]"
        return
    end

    hit = event.get('cti_cache_hit_cnt')
    miss = event.get('cti_cache_miss_cnt')

    key = "cti:#{value_field}:#{attribute}:#{value}"
    misp_data = cache.get(key)
    if misp_data        
        event.set('cti_cache_hit_cnt', hit+1)
    else
        event.set('cti_cache_miss_cnt', miss+1)
        misp_data = get_misp_response(attribute, value)
        if !misp_data.nil?
            # Response with status code 200
            cache.set(key, misp_data, 3600) #60 minutes expiration
        end
    end

    misp_alert = 'unknown'
    if !misp_data.nil?
        #TODO : We may keep CSV in Memcache instead of JSON to improve performance
        obj = JSON.parse(misp_data)
        attributes = obj['response']['Attribute']
        
        misp_alert = 'false'
        if (attributes.count > 0)
            misp_alert = 'true'

            evt = attributes[0]
            event.set("#{label}_category", evt['category'])
            event.set("#{label}_info", evt['Event']['info'])
        end

        event.set(label, misp_alert)
    end

    return [event]
end

def load_misp_cahce(event, cache, value_field, attribute, label)
    value = event.get(value_field)

    if value.nil? or value == ''
        misp_data = "Nothing to do because the field [#{value_field}] is blank [#{value}]"
        return [event]
    end

    key = "#{value_field}:#{attribute}:#{value}"
    misp_data = cache.get(key)
    if misp_data
        #Found - Do nothing
        #puts "### [Found] Getting MISP from cached [#{key}] value [#{value}]"
    else
        #puts "### [Notfound] Getting MISP from field [#{key}] value [#{value}]"
        misp_data = get_misp_response(attribute, value)
        if !misp_data.nil?
            # Response with status code 200
            cache.set(key, misp_data, 3600) #60 minutes expiration
        end
    end

    misp_alert = 'MISP-ERROR'
    if !misp_data.nil?
        obj = JSON.parse(misp_data)
        attributes = obj['response']['Attribute']

        misp_alert = 'false'
        if (attributes.count > 0)
            misp_alert = 'true'
            event.set('misp_alert_category', label)

            if (value_field == 'dst_ip')
                event.set('dst_ip_alert', value)
            end
        end
    end

    event.set(label, misp_alert)
    return [event]
end

def aggregate_stats(cache, event)
    date_key = event.get('@timestamp').to_s
    src_net = event.get('src_net')
    dst_net = event.get('dst_net')

    last_event_dtm = date_key

    yyyy_mm_dd = date_key.split('T')[0]
    yyyy_mm = yyyy_mm_dd[0..6]
    yyyy = yyyy_mm_dd[0..3]
    mm = yyyy_mm_dd[5..6]
    dd = yyyy_mm_dd[8..9]

    pod_name = ENV["POD_NAME"]
    pod_uid = ENV["POD_UID"]
    category = event.get('category')
    alert_misp = event.get('alert_misp')
    misp_alert_category = event.get('misp_alert_category')
    net_pair = "#{src_net}^#{dst_net}"
    
    id = "#{pod_uid}^#{net_pair}^#{category}^#{alert_misp}^#{misp_alert_category}^#{yyyy_mm_dd}^#{yyyy_mm}^#{yyyy}"
    cache_key = "metrics:#{id}"

    obj = { 
        "id" => id,
        "pod" => pod_name,
        "src_net" => src_net,
        "dst_net" => dst_net,
        "category" => category,
        "alert_misp" => alert_misp,
        "misp_alert_category" => misp_alert_category,
        "yyyy_mm_dd" => yyyy_mm_dd,
        "yyyy_mm" => yyyy_mm,
        "yyyy" => yyyy,
        "mm" => mm,
        "dd" => dd,
        "cache_key" => cache_key,
        "last_update_date" => last_event_dtm,
        "metric_event_count" => 1
    }

    metric = cache.get(cache_key)
    if metric
        #Found - Do nothing
        #puts "### [Found] Getting aggregate metrics from field [#{cache_key}]"

        obj = JSON.parse(metric)
        obj["last_update_date"] = last_event_dtm
        obj["cache_key"] = cache_key
        obj["mm"] = mm
        obj["dd"] = dd

        evt_count = obj["metric_event_count"]
        obj["metric_event_count"] = evt_count + 1
    else
        #puts "### [Notfound] Getting aggregate metrics from field [#{cache_key}]"
    end

    json_str = obj.to_json
    #puts json_str

    cache.set(cache_key, json_str, 3600*24*2) #Expiration for 2 days
    event.set("metrics", obj)
end

def add_alert_metadata(event)
    meta_fields = [
        'evt_alert_by_dstip', 
        'evt_alert_by_dstipdmip',
        'evt_alert_by_dmdmip',
        'evt_alert_by_dmdm'
    ]

    arr = []
    meta_fields.each do |field|
        flag = event.get(field)
        if (flag == 'true')
            fn = "#{field}_info"
            fv = event.get(fn)
            kv = "[#{fn} => #{fv}]"
            arr.push(kv)
        end
    end

    if (arr.count > 0)
        metadata = arr.join(",")
        msg = event.get('message')
        event.set('message', "#{msg}\n\e[31m#{metadata}\e[0m")
    end
end

def filter(event)
    data = event.get('message')
    arr1 = data.split(',')
    category = get_category(event, data)

    event.set('evt_category_org', category)
    tokens = populate_event_category(event)
    parse_fields(event, tokens)

    event.set('cti_cache_hit_cnt', 0)
    event.set('cti_cache_miss_cnt', 0)

    load_cti_cahce(event, @mc, 'evt_dst_ip', 'ip-dst', 'evt_alert_by_dstip')
    load_cti_cahce(event, @mc, 'evt_dst_ip', 'domain|ip', 'evt_alert_by_dstipdmip')
    load_cti_cahce(event, @mc, 'evt_domain', 'domain|ip', 'evt_alert_by_dmdmip')
    load_cti_cahce(event, @mc, 'evt_domain', 'domain', 'evt_alert_by_dmdm')
    add_alert_metadata(event)

    populate_ts_aggregate(event)
    create_metric(event)

    ##### OLD #####
    event.set('type', 'syslog')
    event.set('debug_field1', 'not-matched')
    event.set('category', category)

    if category == 'hotspot'
        extract_hotspot(event, data, category)
    elsif category == 'web-proxy'
        data1 = arr1[1]
        extract_webproxy(event, data1, category)
    elsif category == 'dhcp'
        data1 = arr1[1]
        extract_dhcp(event, data1, category)
    elsif category == 'firewall'
        extract_firewall(event, data, category)
    elsif category == 'dns'
        extract_dns(event, data, category)
    end


    load_misp_cahce(event, @mc, 'dst_ip', 'ip-dst', 'alert_misp_dstip_ipdst')
    load_misp_cahce(event, @mc, 'dst_ip', 'domain|ip', 'alert_misp_dstip_domainip')
    load_misp_cahce(event, @mc, 'domain', 'domain|ip', 'alert_misp_domain_domainip')
    load_misp_cahce(event, @mc, 'domain', 'domain', 'alert_misp_domain_domain')

    alert1 = event.get('alert_misp_dstip_ipdst')
    alert2 = event.get('alert_misp_dstip_domainip')
    alert3 = event.get('alert_misp_domain_domainip')
    alert4 = event.get('alert_misp_domain_domain')

    found_alert = 'false'
    if ((alert1 == 'true') || (alert2 == 'true') || (alert3 == 'true') || (alert4 == 'true'))
        found_alert = 'true'
    end
    event.set('alert_misp', found_alert)

    #aggregate_stats(@mc, event)

    return [event]
end
