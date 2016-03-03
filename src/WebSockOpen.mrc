;; /WebSockOpen name uri [timeout]
alias WebSockOpen {
  if ($isid) {
    return
  }

  var %Error, %Sock, %Host, %Ssl, %Port

  ;; Validate inputs
  if ($0 < 2) {
    %Error = Missing paramters
  }
  elseif ($0 > 3) {
    %Error = Excessive Parameters
  }
  elseif (? isin $1 || * isin $1) {
    %Error = names cannot contain ? or *
  }
  elseif ($1 isnum) {
    %Error = names cannot be a numerical value
  }
  elseif ($sock(WebSocket_ $+ $1)) {
    %Error = specified 'name' in use
  }
  elseif ($0 == 3) && ($3 !isnum 1- || . isin $3 || $3 > 300) {
    %Error = Invalid timeout; must be an integer between 1 and 300
  }
  elseif (!$regex(uri, $2, /^((?:wss?:\/\/)?)([^?&#\/\\:]+)((?::\d+)?)((?:[\\\/][^#]*)?)(?:#.*)?$/i)) {
    %Error = Invalid URL specified
  }
  else {
    %Sock = WebSocket_ $+ $1
    %Host = $regml(uri, 2)

    ;; Cleanup after a non-existant socket just to be safe
    if ($hget(%Sock)) {
      ._WebSocket.Cleanup %Sock
    }

    ;; SSL determination
    if (wss:// == $regml(uri, 1)) {
      %Ssl = $true
    }
    else {
      %Ssl = $false
    }

    ;; Port determination
    if ($regml(uri, 3)) {
      %Port = $mid($v1, 2-)
      if (%Port !isnum 1-65535 || . isin %port) {
        %Error = Invalid port specified in uri; must be an interger to between 1 and 65,535
        goto error
      }
    }
    elseif (%Ssl) {
      %Port = 443
    }
    else {
      %Port = 80
    }

    ;; Store state variables
    hadd -m %Sock SOCK_STATE 1
    hadd -m %Sock SOCK_SSL %Ssl
    hadd -m %Sock SOCK_ADDR %Host
    hadd -m %Sock SOCK_PORT %Port
    hadd -m %Sock HTTPREQ_URI $2
    hadd -m %Sock HTTPREQ_RES $iif($len($regml(uri, 4)), $regml(uri, 4), /)
    hadd -m %Sock HTTPREQ_HOST %Host $+ $iif((%Ssl && %Port !== 443) || (!%Ssl && %Port !== 80), : $+ %Port)

    ;; Start timeout timer
    $+(.timer, WebSocket_Timeout_, $1) -oi 1 $iif($3, $v1, 300) _WebSocket.ConnectTimeout %Name

    ;; Begin socket connection and output debug message
    sockopen $iif(%ssl, -e) %sock %host %port
    _WebSocket.Debug -i Connecting> $+ $1 $+ ~Connecting to %host $iif(%ssl, with an SSL connection) on port %port as %sock
  }

  ;; Handle errors
  :error
  if ($error || %error) {
    echo $color(info).dd -s * /WebSockOpen: $v1
    _WebSocket.Debug -e /WebSockOpen~ $+ $v1
    reseterror
    halt
  }
}

;; /_WebSocket.ConnectTimeout name
;; closes a connection that took too long to establish
alias -l _WebSocket.ConnectTimeout {
  if ($isid) {
    return
  }

  ;; output debug message, raise error event, cleanup
  _WebSocket.Debug -e $1 $+ >TIMEOUT Connection timed out
  .signal -n WebSocket_Error_ $+ $1 $1 SOCK_ERROR Connection timeout
  _WebSocket.Cleanup WebSocket_ $+ $1
}

on $*:SOCKOPEN:/^WebSocket_[^\d?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %Key, %Index

  _WebSocket.Debug -i2 SockOpen> $+ $sockname $+ ~Connection established

  ;; Initial error checking
  if ($sockerr) {
    %Error = SOCKOPEN_ERROR $sock($socknamw).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR socket-state hashtable doesn't exist
  }
  elseif ($hget($sockname, SOCK_STATE) !== 1 || !$hget($sockname, HTTPREQ_HOST) || !$hget($Sockname, HTTP_RES)) {
    %Error = INTERNAL_ERROR State doesn't corrospond with attempting to connect
  }
  else {
    _WebSocket.Debug -i SockOpen> $+ %name $+ ~Preparing request head

    ;; Generate a Sec-WebSocket-Key
    bset &SecWebSocketKey 1 $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255)
    noop $encode(&SecWebSocketKey, bm)
    hadd -mb $sockname HTTPREQ_SecWebSocketKey &SecWebSocketKey
    bunset &SecWebSocketKey

    ;; Initial Request: Resource request and required Headers
    hadd -m $sockname HTTPREQ_SecWebSocketKey $_WebSocket.SecKey
    bunset &HTTPREQ
    _WebSocket.BAdd &HTTPREQ GET $hget($sockname, HTTPREQ_RESOURCE) HTTP/1.1
    _WebSocket.BAdd &HTTPREQ Host: $hget($sockname, HTTPREQ_HOST)
    _WebSocket.BAdd &HTTPREQ Connection: upgrade
    _WebSocket.BAdd &HTTPREQ Upgrade: websocket
    _WebSocket.BAdd &HTTPREQ Sec-WebSocket-Version: 13
    _WebSocket.BAdd &HTTPREQ Sec-WebSocket-Key: $hget($sockname, HTTPREQ_SecWebSocketKey)

    ;; Raise init event so scripts can build header list
    .signal -n WebSocket_INIT_ $+ %Name %Name

    ;; Loop over headers, adding them to the request
    %Index = 1
    while ($hfind($sockname, /^HTTPREQ_HEADER\d+_([^\s]+)$/, %Index, r)) {
      _WebSocket.BAdd &HTTPREQ $regml(1) $hget($sockname, $v1)
      inc %Index
    }

    ;; Finalize the request, store the request, and update state variable
    _WebSocket.BAdd &HTTPREQ
    hadd -mb $sockname HTTPREQ_HEAD &HTTPREQ
    hadd -m $sockname SOCK_STATE 2

    ;; Output debug message and begin sending the request
    _WebSocket.Debug -i SockOpen> $+ %Name $+ ~Sending HTTP request
    _WebSocket.Send $sockname
  }

  ;; Handle errors
  :error
  if ($error || %Error) {
    %Error = $v1
    reseterror

    ;; Log error, raise error event, cleanup socket
    _WebSocket.Debug -e SockOpen> $+ %Name $+ ~ $+ %Error
    .signal -n WebSocket_ERROR_ $+ %Name %Name %Error
    hadd -m $sockname SOCK_STATE 0
    _WebSocket.Cleanup $sockname
  }
}