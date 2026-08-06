// Minimal hot-path MTProto/TL schema used by TRLib examples.
resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector<long> = ResPQ;
rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult;
rpc_error#2144ca19 error_code:int error_message:string = RpcError;
pong#347773c5 msg_id:long ping_id:long = Pong;
new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession;
msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
gzip_packed#3072cfa1 packed_data:string = Object;
msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;
bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification;
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification;

---functions---
req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
ping_delay_disconnect#f3427b8c ping_id:long disconnect_delay:int = Pong;
