#Example : https://fabianlee.org/2017/04/24/elk-using-ruby-in-logstash-filters/
#Labels {'user', 'domain', 'src_ip', 'dst_ip', 'mac', 'src_net', 'dst_net', 'src_port', 'dst_port'}

def register(params)
end

def filter(event)
    data = event.get('message')
    arr1 = data.split(',')
    category = arr1[0]
    event.set('debug_field1', 'not-matched')

    if category == 'hotspot'
        #hotspot,account,info,debug 0-Napbiotec: seubpong.mon (192.168.20.29): logged in
        groups = data.scan(/^.*:\s(.+?)\s\((.+?)\):.+$/i)[0]
        user = groups[0]
        src_ip = groups[1]

        event.set('user', user.strip)
        event.set('src_ip', src_ip.strip)
        event.set('debug_field1', category)
    elsif category == 'web-proxy'
        data1 = arr1[1]
        #   0         1              2        3                  4                            5
        #account 0-Napbiotec: 192.168.20.115 GET http://cu.bwc.brother.com/certset/ver  action=allow cache=MISS        
        arr2 = data1.split(' ')
        src_ip = arr2[2]
        url = arr2[4]

        event.set('src_ip', src_ip.strip)
        event.set('domain', URI.parse(url).host)
        event.set('debug_field1', category)
    elsif category == 'dhcp'
        data1 = arr1[1]
        # 0        1         2      3           4         5       6   
        #info 0-Napbiotec: dhcp6 assigned 192.168.30.236 to E2:9B:9D:A9:DF:5B
        arr2 = data1.split(' ')
        src_ip = arr2[4]
        mac = arr2[6]

        event.set('src_ip', src_ip.strip)
        event.set('mac', mac)
        event.set('debug_field1', category)
    elsif category == 'firewall'
        #   0                1          2            3               4           5             6           7    8        9                          10                    11                
        # firewall,info 0-Napbiotec: forward: in:vlan20-office out:pppoe-tot, src-mac b4:0f:b3:1d:63:4b, proto TCP (ACK,FIN,PSH), 192.168.20.171:43996->47.241.18.42:443, NAT (192.168.20.171:43996->125.25.69.110:43996)->47.241.18.42:443, len 71

        if data.include? "NAT"
            groups = data.scan(/^.*?in:(.+?)\s+out:(.+?),\s*src-mac\s+(.+?),.*,\s*(.+?):(.+?)->(.+?):(.+?),\sNAT\s(.*)$/i)[0]
        else
            groups = data.scan(/^.*?in:(.+?)\s+out:(.+?),\s*src-mac\s+(.+?),.*,\s*(.+?):(.+?)->(.+?):(.+?),\slen\s(.*)$/i)[0]
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
    end
    
    return [event]
end
