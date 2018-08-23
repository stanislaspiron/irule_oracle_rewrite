# irule_oracle_rewrite

In SQLNET*2 Protocol, the client first connect to service TCP/1521 and send expected Database. The oracle database server redirect to the expected database service containing IP and port.

When load balancing Oracle SQLNET*2 database, if the server hosts the target database, the client will try to connect to the server and bypass the load balancer.

This irule allow to rewrite the pool member address with the virtual server address with binary encoding the new response with new data size.

There are 2 versions of this code:

- LTM_oracle_tns_rewrite.tcl  
  this file allow to rewrite the response with virtual server address. another virtual server is required listening on any ports to forward secondary tcp connection.
- LTM_oracle_tns_ALG.tcl  
  this file allow to rewrite the response with virtual server address. This code allow dynamically the secondary TCP connection based on the redirect data.
  
