when CLIENT_ACCEPTED {
	set virtual_ip [getfield [IP::local_addr] "%" 1]
	set client_ip [getfield [IP::remote_addr] "%" 1]
	set client_vlan [LINK::vlan_id]
}

when SERVER_CONNECTED {
	set server_ip [getfield [IP::remote_addr] "%" 1]
	set server_vlan [LINK::vlan_id]
	TCP::collect
}

when SERVER_DATA {
	set tns_data [TCP::payload]
	incr collected_length [TCP::payload length]
	# Detect if the response is a redirect
	if {[binary scan $tns_data SSccSSA* packet_length packet_checksum type reserved_byte header_checksum redirect_length redirect_data] == 7 && $type == 5 && \
		[set new_redirect_data [string map "(HOST=$server_ip) (HOST=$virtual_ip)" $redirect_data]] ne $redirect_data } {
			set new_redirect_length [string length $new_redirect_data]
			TCP::payload replace 0 [TCP::payload length] [binary format SSccSSA* [expr {$new_redirect_length+10}] $packet_checksum $type $reserved_byte $header_checksum $new_redirect_length $new_redirect_data]
			#Collect the target port in the redirect response
			set redirect_port [findstr $redirect_data "(PORT=" 6 ")"]
			# Create the new dynamic listener only for client source IP
			listen {
				proto 6
				timeout 30
				bind $client_vlan $virtual_ip $redirect_port
				server $server_ip $redirect_port
				allow $client_ip
			}
	}

	TCP::release
	# Collect only the first 4096 bytes.
	if {$collected_length < 4096} {
		TCP::collect
	}
}
