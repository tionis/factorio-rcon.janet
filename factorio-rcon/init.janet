(def failedAuthResponseID -1)

(def packet-types
  {:auth 3
   :auth-response 2
   :exec-command 2
   :response-value 0})

(def- packetPaddingSize 2)
(def- packetHeaderFieldSize 4)
(def- packetHeaderSize (* packetHeaderFieldSize 2))

(defn new-packet [typ body]
  {:size (+ (length body) packetHeaderSize packetPaddingSize)
   :id (first (peg/match ~(int 4) (os/cryptorand 4)))
   :type typ
   :body body})

(defn encode-packet [packet]
  (def buf (buffer/new (+ (packet :size) packetHeaderFieldSize)))
  (buffer/push buf (slice (int/to-bytes (int/s64 (packet :size)) :le) 0 4))
  (buffer/push buf (slice (int/to-bytes (int/s64 (packet :id)) :le) 0 4))
  (buffer/push buf (slice (int/to-bytes (int/s64 (packet :type)) :le) 0 4))
  (buffer/push buf (packet :body))
  (buffer/push buf "\0") # NULL-terminated string
  (buffer/push buf "\0") # Write padding
  buf)

(defn write-packet [connection packet] (ev/write connection (encode-packet packet)))

(defn read-packet [connection]
  (def packet @{})
  (put packet :size (first (peg/match ~(int 4) (net/read connection 4))))
  (put packet :id (first (peg/match ~(int 4) (net/read connection 4))))
  (put packet :type (first (peg/match ~(int 4) (net/read connection 4))))
  (def buf (net/chunk connection (- (packet :size) packetHeaderSize)))
  (put packet :body (string/trimr (string buf) "\0"))
  packet)

(defn dial [address]
  (net/connect ;(string/split ":" address) :stream))

(defn execute [connection command]
  (def packet (new-packet (packet-types :exec-command) command))
  (write-packet connection packet)
  (def response (read-packet connection))
  (if (not= (response :id) (packet :id)) (error "rcon: packets from server received out of order"))
  (response :body))

(defn authenticate [connection password]
  (def packet (new-packet (packet-types :auth) password))
  (write-packet connection packet)
  (var response (read-packet connection))
  # The server will potentially send a blank ResponseValue packet before giving
  # back the correct AuthResponse. This can safely be discarded, as documented here:
  # https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#SERVERDATA_AUTH_RESPONSE
  (if (= (response :type) (packet-types :response-value))
    (set response (read-packet connection)))
  (if (not= (response :type) (packet-types :auth-response))
    (error "received two non auth-response answers"))
  (if (= (response :id) failedAuthResponseID)
    (error "rcon: authentication failed"))
  (if (not= (response :id) (packet :id))
    (error "rcon: invalid response ID from remote connection"))
  :success)
