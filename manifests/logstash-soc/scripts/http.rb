require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'

def register(params)
    $stdout.sync = true
end

def populate_ts_aggregate(event)
    dtm = DateTime.now
    dtm += Rational('7/24') # Thailand timezone +7

    event.set('cust_ts_yyyy', dtm.year)
    event.set('cust_ts_mm', dtm.mon.to_s.rjust(2,'0'))
    event.set('cust_ts_dd', dtm.mday.to_s.rjust(2,'0'))
    event.set('cust_ts_hh', dtm.hour.to_s.rjust(2,'0'))
    event.set('cust_ts_wd', dtm.wday.to_s.rjust(2,'0'))
end

def filter(event)
    populate_ts_aggregate(event)
    
    cust_ts_yyyy = event.get('cust_ts_yyyy')
    cust_ts_mm = event.get('cust_ts_mm')
    cust_ts_dd = event.get('cust_ts_dd')

    full_index_name = "onix-v2-#{cust_ts_yyyy}-#{cust_ts_mm}-#{cust_ts_dd}"
    event.set('index_name', full_index_name)

    return [event]
end
