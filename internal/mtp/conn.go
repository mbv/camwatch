package mtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

var errDeadline = errors.New("mtp: deadline exceeded")

// DialOptions carries cloud vendor_params for MTP (vendor 6).
type DialOptions struct {
	SSAddrs      []string
	AuthStr      string
	AuthToken    string
	DID          string
	UID          string
	CallerUUID   string
	SSVer        string
	LocalIP      net.IP // camera LAN IP for optional CNT\x00
	DevicePublic string // unused; retained for DialOptions callers
	// Native MTP keypair for CNT type 0x0002. This is independent of the
	// cloud app keypair and remains stable across vendor credential refreshes.
	MTPPrivate string // hex
	MTPPublic  string // hex
}

// Conn implements miss.Conn over Xiaomi MTP (CNT + KCP + MTP).
type Conn struct {
	udp      *net.UDPConn
	remote   *net.UDPAddr
	session  []byte
	token    []byte
	kcp      *kcpState
	authTok  string
	ssVer    string
	shareKey []byte // CNT beforenm — AES-128-CBC for transport MTP/login
	signKey  []byte // HMAC(shareKey,shareKey) for transport PacketSign
	clientPriv []byte // Curve25519 private (CNT type 0x0002); needed for media ECDH
	mediaKey   []byte // beforenm(clientPriv, LoginResponse 0x0002) — ChaCha for CNT~/CHK~
	mediaSign  []byte // HMAC(mediaKey,mediaKey) for media CNT PacketSign

	// pendingCNT holds post-connect type3||type4 until transport login.
	pendingCNT []byte

	mtpSeq uint32

	// App-layer state after native LoginResponse (msgid=7).
	loginCtx       *loginContext
	localIP        net.IP
	cameraIP       net.IP
	channelSession []byte // MSIP 0x001e
	loginReqID     uint32 // MSIP 0x0009 echoed from LoginResponse
	mediaEndpoints []mediaEndpoint
	appAuthed      atomic.Bool
	mediaStarted   atomic.Bool
	mediaSess      atomic.Pointer[mediaSession] // set once media KCP is up
	mediaRX        chan []byte                 // CNT~ demux during bind dance

	// Extra-ssAddr transport sessions sharing :40000. We ACK their KCP so the
	// servers stop retransmitting LoginResponse/SessAck; we never decrypt them.
	foreignMu  sync.Mutex
	foreignKCP map[[8]byte]*kcpState
	foreignLog sync.Map // session hex → logged once

	channels *channelSet
	deadline atomic.Value // time.Time

	errMu     sync.Mutex
	err       error
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *Conn) writeUDP(pkt []byte) (int, error) {
	if c.remote != nil {
		return c.udp.WriteToUDP(pkt, c.remote)
	}
	return c.udp.Write(pkt)
}

// Dial connects via MTP, trying ssAddrs in order until CNT + transport login succeed.
func Dial(opt DialOptions) (*Conn, error) {
	if len(opt.SSAddrs) == 0 {
		return nil, fmt.Errorf("mtp: no ssAddrs")
	}
	if opt.AuthStr == "" || opt.AuthToken == "" {
		return nil, fmt.Errorf("mtp: authStr/authToken required")
	}
	if len(opt.AuthStr) != authStrLen {
		return nil, fmt.Errorf("mtp: authStr length %d want %d", len(opt.AuthStr), authStrLen)
	}
	Logp("mtp: dial authStr=%d authToken=%d ssAddrs=%v\n", len(opt.AuthStr), len(opt.AuthToken), opt.SSAddrs)

	var clientPriv, clientPub []byte
	var err error
	if opt.MTPPrivate != "" && opt.MTPPublic != "" {
		clientPriv = mustHex32(opt.MTPPrivate)
		clientPub = mustHex32(opt.MTPPublic)
		if len(clientPriv) != 32 || len(clientPub) != 32 {
			return nil, fmt.Errorf("mtp: bad native client keypair")
		}
		Logp("mtp: using native MTP keypair (type2)\n")
	} else {
		clientPriv, clientPub, err = generateCNTKeypair()
		if err != nil {
			return nil, err
		}
		Logf("mtp: generated ephemeral CNT keypair\n")
	}

	// Serial dial (one ssAddr): parallel probes created three sessions and
	// noisy post-connect races; Mi Home also settles on one CNT peer.
	var lastErr error
	for _, addr := range opt.SSAddrs {
		ip, port, err := resolveSSAddr(addr)
		if err != nil {
			lastErr = fmt.Errorf("mtp: %s: %w", addr, err)
			Logf("mtp: ssAddr %s failed: %v\n", addr, err)
			continue
		}
		c, err := dialOne(ip, port, clientPriv, clientPub, opt)
		if err != nil {
			lastErr = fmt.Errorf("mtp: %s: %w", addr, err)
			Logf("mtp: ssAddr %s failed: %v\n", addr, err)
			continue
		}
		return c, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("mtp: all ssAddrs failed")
	}
	return nil, lastErr
}

func resolveSSAddr(addr string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "30005"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("mtp: bad port in %s", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, 0, fmt.Errorf("mtp: resolve %s: %w", host, err)
		}
		ip = ips[0]
	}
	return ip, port, nil
}

func dialOne(ip net.IP, port int, clientPriv, clientPub []byte, opt DialOptions) (*Conn, error) {
	// Native: one UDP :40000 for signalling + LAN + media (pcap).
	remote := &net.UDPAddr{IP: ip, Port: port}
	var udp *net.UDPConn
	var err error
	for _, localPort := range []int{mediaUDPPort, 0} {
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	Logf("mtp: UDP local=%v remote=%v\n", udp.LocalAddr(), remote)

	writeRemote := func(pkt []byte) (int, error) {
		return udp.WriteToUDP(pkt, remote)
	}

	// Mi Home retries CNT for ~15s per auth before refreshing miss_get_vendor
	// (playback_2.pcapng). Rebuild nonce/seq each send; keep the same type2 key.
	const probeBudget = 18 * time.Second
	deadline := time.Now().Add(probeBudget)
	buf := make([]byte, 2048)
	var reply []byte
	seq := uint32(1)

	Logp("mtp: probing CNT %s for up to %s\n", remote, probeBudget)

	for time.Now().Before(deadline) {
		pkt, err := buildConnectCNT(ip, opt.AuthStr, opt.AuthToken, seq, clientPub)
		if err != nil {
			_ = udp.Close()
			return nil, err
		}
		// Send duplicated (1080) and single (540) — success in pcap used 540.
		if _, err = writeRemote(pkt); err != nil {
			_ = udp.Close()
			return nil, err
		}
		_, _ = writeRemote(pkt[:len(pkt)/2])

		_ = udp.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		n, _, err := udp.ReadFromUDP(buf)
		if err != nil {
			seq++
			continue
		}
		Logp("mtp: CNT reply from %v len=%d magic=%q sess=%x\n", remote, n, buf[:min(4, n)], buf[4:min(12, n)])
		if n >= 16 && string(buf[0:4]) == magicCNT && !isZero(buf[4:12]) {
			reply = append([]byte(nil), buf[:n]...)
			break
		}
		seq++
	}
	if reply == nil {
		_ = udp.Close()
		return nil, fmt.Errorf("timeout waiting for CNT session")
	}

	session, serverKey, connectionID, replyTxn, err := parseCNTReply(reply)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	Logp("mtp: CNT session %x serverKey=%dB conn=%08x txn=%08x\n",
		session, len(serverKey), connectionID, replyTxn)

	okSign, win := verifyServerSignCNT(reply, opt.AuthToken)
	Logf("mtp: CNT reply ServerSign(authToken)=%v window=%s\n", okSign, win)

	shareKey, err := deriveShareKey(clientPriv, serverKey)
	if err != nil {
		_ = udp.Close()
		if len(serverKey) == 0 {
			// The opaque "sharekey needs 32-byte keys (priv=32 pub=0)" from
			// deriveShareKey doesn't say why pub is empty: this ssAddr's CNT
			// reply carried no TLV 0x0002 (ECDH key material). Surface that
			// directly so it reads as "bad/stale ssAddr", not a crypto bug.
			return nil, fmt.Errorf("mtp: CNT reply from %s missing server ECDH key (TLV 0x0002): %w", remote, err)
		}
		return nil, err
	}
	replyPlain, ok := decryptCNTCipherArea(reply, shareKey)
	if !ok {
		Logf("mtp: CNT reply cipher decrypt failed (shareKey=cnt-beforenm)\n")
	} else {
		Logf("mtp: CNT reply cipher plain=%d head=%x\n",
			len(replyPlain), replyPlain[:min(16, len(replyPlain))])
	}

	// Prove the advertised CNT public matches the private used for beforenm.
	wantPub, err := curve25519.X25519(clientPriv, curve25519.Basepoint)
	if err != nil || !bytes.Equal(wantPub, clientPub) {
		_ = udp.Close()
		return nil, fmt.Errorf("mtp: native keypair mismatch")
	}

	shareSignKey := deriveShareSignKey(shareKey)
	token := append([]byte(nil), shareKey[:16]...)

	loginCtx, err := newLoginContext(
		opt.AuthStr, clientPub, ip, uint16(port), connectionID, replyTxn,
		opt.DID, opt.UID, opt.CallerUUID,
	)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	if relay := tlvValue(replyPlain, tlvMappedAddr); len(relay) == fieldAddrAttrLen {
		loginCtx.relayAddr = append([]byte(nil), relay...)
		rport := binary.BigEndian.Uint16(relay[2:4])
		Logf("mtp: CNT reply TLV 0x0015 relay=%v:%d raw=%x\n",
			net.IP(relay[4:8]), rport, relay[:min(8, len(relay))])
	}
	if v, err := strconv.ParseUint(opt.SSVer, 10, 32); err == nil && v > 0 {
		loginCtx.ssVer = uint32(v)
	}

	_ = udp.SetDeadline(time.Time{})
	if opt.LocalIP != nil && !opt.LocalIP.Equal(ip) {
		go func(sess []byte, lanIP net.IP) {
			lan, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: lanIP, Port: mediaUDPPort})
			if err != nil {
				return
			}
			defer lan.Close()
			msg := buildLANCNT(sess)
			for i := 0; i < 3; i++ {
				_, _ = lan.Write(msg)
				time.Sleep(200 * time.Millisecond)
			}
		}(session, opt.LocalIP)
	}

	loginCtx.timestamp = uint64(time.Now().UnixMilli())
	loginCtx.loginHexTS = ""
	loginCtx.loginReqID = loginCtx.connectionID & connIDMask
	// Mi Home post-CNT uses replyTxn+3/+4 (pcap); +1/+2 are consumed internally.
	loginCtx.transaction = replyTxn
	_ = loginCtx.nextTransaction()
	_ = loginCtx.nextTransaction()

	c := &Conn{
		udp:      udp,
		remote:   remote,
		session:  session,
		token:    token,
		kcp:      newKCP(session, shareSignKey),
		authTok:  opt.AuthToken,
		ssVer:    opt.SSVer,
		mtpSeq:   seq,
		loginCtx: loginCtx,
		// localip query is the camera LAN address (0x0014); 0x0013 uses outbound iface.
		cameraIP:   opt.LocalIP,
		channels:   newChannelSet(),
		closed:     make(chan struct{}),
		shareKey:   append([]byte(nil), shareKey...),
		signKey:    append([]byte(nil), shareSignKey...),
		clientPriv: append([]byte(nil), clientPriv...),
		foreignKCP: make(map[[8]byte]*kcpState),
	}
	c.deadline.Store(time.Time{})
	Logp("mtp: session ready token=%x enc=%dB\n", token, len(shareKey))

	if err = c.loginTransport(loginCtx, shareSignKey, ip, uint16(port)); err != nil {
		_ = udp.Close()
		return nil, err
	}
	// Extra ssAddr logins (9 endpoints) leave foreign KCP on this socket and
	// often prevent server punch / media KCP~. Primary LoginResponse's 3
	// endpoints are enough (collectExtraMediaEndpoints left unused for now).
	go c.worker()
	c.startMediaProbes()
	return c, nil
}

func (c *Conn) loginTransport(ctx *loginContext, shareSignKey []byte, ip net.IP, port uint16) error {
	// Native: post-CNT phases, then one KCP PUSH (pre-login plain without 0x0023).
	// A later login plain (with 0x0023=0x10) is a retry/second phase if needed.
	buildPost := func(changeFlags, closeFlags uint32, seqDelta uint32, ts uint64) []byte {
		ctx.changeFlags = changeFlags
		ctx.closeFlags = closeFlags
		ctx.timestamp = ts
		txn := ctx.nextTransaction()
		seq := c.mtpSeq + seqDelta
		return buildPostConnectCNT(
			c.session, ip, port, seq, ctx, txn, ts,
			c.shareKey, shareSignKey,
		)
	}

	sendUDP := func(pkt []byte, label string) error {
		Logf("mtp: TX %s len=%d\n", label, len(pkt))
		_, err := c.writeUDP(pkt)
		return err
	}

	sendMTP := func(plain []byte, label string) error {
		seq := c.nextMTPSeq()
		ctx.timestamp = uint64(time.Now().UnixMilli())
		if ctx.loginHexTS == "" {
			ctx.loginHexTS = fmt.Sprintf("%016x", ctx.timestamp)
		}
		txn := ctx.nextTransaction()
		mtpPkt := buildMTPAt(
			c.session, c.token, c.shareKey, c.signKey, mtpMsgLogin, seq, 4,
			plain, txn, ctx.timestamp,
		)
		kcpPkt := c.kcp.buildPUSH(mtpPkt)
		Logf("mtp: TX %s seq=%d txn=%08x kcp=%d mtp=%d plain=%d\n",
			label, seq, txn, len(kcpPkt), len(mtpPkt), len(plain))
		_, err := c.writeUDP(kcpPkt)
		return err
	}

	baseTS := uint64(time.Now().UnixMilli())
	ctx.timestamp = baseTS
	if ctx.loginHexTS == "" {
		ctx.loginHexTS = fmt.Sprintf("%016x", baseTS)
	}

	post1 := buildPost(0, 1, 1, baseTS)
	post2 := buildPost(0, 0, 2, baseTS)
	post3 := buildPost(changeFlagEnable, 0, 3, baseTS+1)
	c.mtpSeq += 3

	if err := sendUDP(post1, "postCNT 0x23=0 0x19=1"); err != nil {
		return err
	}
	if err := sendUDP(post2, "postCNT 0x23=0 0x19=0"); err != nil {
		return err
	}
	if err := sendMTP(ctx.transportPlainPre(), "pre-login"); err != nil {
		return err
	}
	// Native follows the first KCP with another post-CNT (0x23=0x10).
	if err := sendUDP(post3, "postCNT 0x23=0x10 0x19=0"); err != nil {
		return err
	}

	deadline := time.Now().Add(5 * time.Second)
	nextRetry := time.Now().Add(300 * time.Millisecond)
	retries := 0
	sentLogin := false
	buf := make([]byte, 2048)

	for time.Now().Before(deadline) {
		readUntil := deadline
		if nextRetry.Before(readUntil) {
			readUntil = nextRetry
		}
		_ = c.udp.SetReadDeadline(readUntil)
		n, _, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Now().Before(deadline) && retries < 6 {
					if !sentLogin && retries >= 1 {
						// Second phase: login plain with 0x0023=0x10.
						if err := sendMTP(ctx.transportPlain(), "login"); err != nil {
							return err
						}
						sentLogin = true
					} else {
						_ = sendUDP(post1, "postCNT retry1")
						_ = sendUDP(post2, "postCNT retry2")
						_ = sendMTP(ctx.transportPlainPre(), "pre-login retry")
						_ = sendUDP(post3, "postCNT 0x10 retry")
						if sentLogin {
							_ = sendMTP(ctx.transportPlain(), "login retry")
						}
					}
					retries++
					nextRetry = time.Now().Add(300 * time.Millisecond)
					continue
				}
				break
			}
			return err
		}
		Logf("mtp: RX during login len=%d magic=%q\n", n, buf[:min(4, n)])
		if c.handleTransportPacket(buf[:n]) {
			atomic.StoreUint32(&c.mtpSeq, max(atomic.LoadUint32(&c.mtpSeq), 7))
			_ = c.udp.SetDeadline(time.Time{})
			Logp("mtp: native transport login complete\n")
			return nil
		}
	}
	return fmt.Errorf("mtp: timeout waiting for native LoginResponse")
}

func parseCNTLoginTxn(pkt []byte) (uint32, bool) {
	if len(pkt) < 48 || !strings.HasPrefix(string(pkt[:4]), "CNT") {
		return 0, false
	}
	body := pkt[16:]
	off := 0
	if len(body) >= 32 {
		inner := int(binary.BigEndian.Uint16(body[24:26]))
		padHdr := binary.BigEndian.Uint32(body[28:32])
		if 28+inner <= len(body) && padHdr >= 1 && padHdr <= 16 {
			off = 28 + inner
			if off+4 <= len(body) && binary.BigEndian.Uint32(body[off:off+4]) == 0 {
				off += 4
			}
		}
	}
	for off+4 <= len(body) {
		t := binary.BigEndian.Uint16(body[off : off+2])
		l := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if l < 0 || off+l > len(body) {
			break
		}
		val := body[off : off+l]
		off += l
		if t == tlvTransactionID && l >= 4 {
			return binary.BigEndian.Uint32(val[:4]), true
		}
		if t == tlvServerSign || t == tlvPacketSign {
			break
		}
	}
	return 0, false
}

func (c *Conn) handleTransportPacket(pkt []byte) bool {
	if len(pkt) < 4 {
		return false
	}
	if strings.HasPrefix(string(pkt[:4]), "CNT") {
		Logf("mtp: RX CNT during login len=%d sess=%x\n", len(pkt), pkt[4:min(12, len(pkt))])
		if len(pkt) >= 16 {
			Logf("mtp: CNT hdr msgid=%x blen=%d body=%x\n",
				pkt[12:14], binary.BigEndian.Uint16(pkt[14:16]), pkt[16:min(80, len(pkt))])
			if plain, ok := decryptCNTCipherArea(pkt, c.shareKey); ok {
				Logf("mtp: CNT cipher plain=%d head=%x\n",
					len(plain), plain[:min(32, len(plain))])
			}
			// Walk clear TLVs for result codes / errors.
			body := pkt[16:]
			off := 0
			if len(body) >= 32 {
				inner := int(binary.BigEndian.Uint16(body[24:26]))
				padHdr := binary.BigEndian.Uint32(body[28:32])
				if 28+inner <= len(body) && padHdr >= 1 && padHdr <= 16 {
					off = 28 + inner
					if off+4 <= len(body) && binary.BigEndian.Uint32(body[off:off+4]) == 0 {
						off += 4
					}
				}
			}
			for off+4 <= len(body) {
				t := binary.BigEndian.Uint16(body[off : off+2])
				l := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
				off += 4
				if l < 0 || off+l > len(body) {
					break
				}
				val := body[off : off+l]
				off += l
				Logf("mtp: CNT TLV 0x%04x len=%d val=%x\n", t, l, val[:min(32, len(val))])
				if t == tlvServerSign || t == tlvPacketSign {
					break
				}
			}
		}
		return false
	}
	if !strings.HasPrefix(string(pkt[:4]), "KCP") {
		return false
	}
	cmd, sn, una, payload, ok := parseKCP(pkt)
	if !ok {
		return false
	}
	atomic.StoreUint32(&c.kcp.una, una)
	if cmd == kcpCmdACK {
		Logp("mtp: RX native login ACK sn=%d una=%d\n", sn, una)
		return false
	}
	if cmd != kcpCmdPush {
		return false
	}
	_, _ = c.writeUDP(c.kcp.buildACK(sn, sn+1))
	if len(payload) < 48 || string(payload[:4]) != magicMTP {
		return false
	}
	msgID, seq, token, enc, err := parseMTP(payload)
	if err != nil {
		return false
	}
	padOrTyp := uint32(0)
	if len(enc) >= 4 {
		padOrTyp = binary.BigEndian.Uint32(enc[:4])
	}
	if len(token) == 16 {
		c.token = token
	}
	Logf("mtp: RX native response msgid=%d seq=%d pad/typ=%d blob=%d\n",
		msgID, seq, padOrTyp, len(enc))
	// LoginResponse: msgid=7, AES-CBC padLen in 1..16.
	if msgID != mtpMsgLoginResp || padOrTyp < 1 || padOrTyp > 16 {
		return false
	}
	plain, err := decryptMTPPayload(enc, c.shareKey)
	if err != nil {
		Logf("mtp: native LoginResponse decrypt: %v\n", err)
		return false
	}
	Logf("mtp: native LoginResponse plain=%d\n", len(plain))
	c.applyLoginResponse(plain)
	return true
}

func (c *Conn) applyLoginResponse(plain []byte) {
	// Dump every TLV — look for mapped (0x0015), probed (0x0006), stun servers (0x002d).
	Logf("mtp: LoginResponse TLVs %s\n", summarizeTLVs(plain))
	for _, t := range []uint16{tlvProbedAddrs, 0x0007, tlvMappedAddr, tlvStunAddrs} {
		if v := tlvValue(plain, t); len(v) > 0 {
			Logf("mtp: LoginResponse 0x%04x len=%d head=%x\n", t, len(v), v[:min(32, len(v))])
		}
	}
	if v := tlvValue(plain, tlvChannelSession); len(v) == fieldChannelSessionLen {
		c.channelSession = append([]byte(nil), v...)
		Logp("mtp: LoginResponse tlvChannelSession channelSession=%x\n", c.channelSession)
	}
	if v := tlvValue(plain, tlvRequestID); len(v) >= 4 {
		c.loginReqID = binary.BigEndian.Uint32(v[:4])
		Logf("mtp: LoginResponse tlvRequestID reqID=%08x\n", c.loginReqID)
	}
	// Frida: after LoginResponse ACK, native mtp_sharekey_create with LoginResponse
	// tlvPublicKey server pub → ChaCha media key (≠ AES CNT beforenm used for transport).
	if v := tlvValue(plain, tlvPublicKey); len(v) >= 36 && len(c.clientPriv) == 32 {
		pub := v[4:36]
		if mk, err := deriveShareKey(c.clientPriv, pub); err == nil {
			c.mediaKey = mk
			c.mediaSign = deriveShareSignKey(mk)
			Logf("mtp: media ChaCha key from LoginResponse tlvPublicKey (pub=%x…)\n", pub[:8])
		} else {
			Logf("mtp: media sharekey derive: %v\n", err)
		}
	}
	if v := tlvValue(plain, tlvMediaEndpoints); len(v) >= 4 {
		c.mediaEndpoints = parseMediaEndpoints(v)
		for i, ep := range c.mediaEndpoints {
			Logf("mtp: LoginResponse media[%d] %s:%d sess=%x kind=%#x\n",
				i, ep.IP, ep.Port, ep.Session, ep.Kind)
		}
	}
	// Native pcap: MediaBinding/CNT| 0x0015 = LoginResponse MA_MAPPED_ADDR
	// (93.84.x:44128), not STUN XOR-MAPPED / punch-ack echo (46.205.x).
	if c.loginCtx != nil {
		if v := tlvValue(plain, tlvMappedAddr); len(v) == fieldAddrAttrLen && (v[4]|v[5]|v[6]|v[7]) != 0 {
			c.loginCtx.buddyAddr = append([]byte(nil), v...)
			Logf("mtp: LoginResponse MA_MAPPED_ADDR buddy tlvMappedAddr %v:%d\n",
				net.IP(v[4:8]), binary.BigEndian.Uint16(v[2:4]))
		}
		if v := tlvValue(plain, tlvStunAddrs); len(v) > 0 {
			c.loginCtx.stunAddrs = append([]byte(nil), v...)
			Logf("mtp: LoginResponse MA_STUN_ADDRS len=%d head=%x\n", len(v), v[:min(32, len(v))])
		}
		if v := tlvValue(plain, tlvHexTimestamp); len(v) > 0 {
			end := min(16, len(v))
			if s := string(bytes.TrimRight(v[:end], "\x00")); s != "" {
				c.loginCtx.loginHexTS = s
			}
		}
	}
}

// mediaShareKey returns the ChaCha key for CNT~/CHK~ (LoginResponse ECDH),
// falling back to transport shareKey only if media key was never derived.
func (c *Conn) mediaShareKey() []byte {
	if len(c.mediaKey) == 32 {
		return c.mediaKey
	}
	return c.shareKey
}

func (c *Conn) mediaSignKey() []byte {
	if len(c.mediaSign) == 32 {
		return c.mediaSign
	}
	return deriveShareSignKey(c.mediaShareKey())
}

// collectExtraMediaEndpoints logs into the remaining ssAddrs on the same :40000
// socket (native pcap: 3 sessions → 9 media endpoints) and merges endpoints.
func (c *Conn) collectExtraMediaEndpoints(opt DialOptions, clientPriv, clientPub []byte) {
	if c.udp == nil || c.remote == nil {
		return
	}
	primary := c.remote.String()
	before := len(c.mediaEndpoints)
	for _, addr := range opt.SSAddrs {
		ip, port, err := resolveSSAddr(addr)
		if err != nil {
			continue
		}
		remote := &net.UDPAddr{IP: ip, Port: port}
		if remote.String() == primary {
			continue
		}
		eps, err := c.loginExtraSSAddr(remote, clientPriv, clientPub, opt)
		if err != nil {
			Logf("mtp: extra ssAddr %s: %v\n", addr, err)
			continue
		}
		c.mediaEndpoints = append(c.mediaEndpoints, eps...)
	}
	Logp("mtp: media endpoints primary=%d total=%d\n", before, len(c.mediaEndpoints))
}

func (c *Conn) loginExtraSSAddr(remote *net.UDPAddr, clientPriv, clientPub []byte, opt DialOptions) ([]mediaEndpoint, error) {
	buf := make([]byte, 2048)
	var reply []byte
	for seq := uint32(1); seq <= 8; seq++ {
		pkt, err := buildConnectCNT(remote.IP, opt.AuthStr, opt.AuthToken, seq, clientPub)
		if err != nil {
			return nil, err
		}
		if _, err := c.udp.WriteToUDP(pkt[:len(pkt)/2], remote); err != nil {
			return nil, err
		}
		_ = c.udp.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, addr, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if addr != nil && !addr.IP.Equal(remote.IP) {
			continue
		}
		if n >= 16 && string(buf[0:4]) == magicCNT && !isZero(buf[4:12]) {
			reply = append([]byte(nil), buf[:n]...)
			break
		}
	}
	if reply == nil {
		return nil, fmt.Errorf("no CNT reply")
	}
	session, serverKey, connectionID, replyTxn, err := parseCNTReply(reply)
	if err != nil {
		return nil, err
	}
	shareKey, err := deriveShareKey(clientPriv, serverKey)
	if err != nil {
		return nil, err
	}
	loginCtx, err := newLoginContext(
		opt.AuthStr, clientPub, remote.IP, uint16(remote.Port), connectionID, replyTxn,
		opt.DID, opt.UID, opt.CallerUUID,
	)
	if err != nil {
		return nil, err
	}
	loginCtx.transaction = replyTxn
	_ = loginCtx.nextTransaction()
	_ = loginCtx.nextTransaction()
	shareSign := deriveShareSignKey(shareKey)
	token := append([]byte(nil), shareKey[:16]...)

	// Minimal post-connect + login (same shape as primary).
	ts := uint64(time.Now().UnixMilli())
	loginCtx.timestamp = ts
	loginCtx.changeFlags = 1
	loginCtx.closeFlags = 0
	post := buildPostConnectCNT(
		session, remote.IP, uint16(remote.Port), 1, loginCtx, loginCtx.nextTransaction(), ts,
		shareKey, shareSign,
	)
	_, _ = c.udp.WriteToUDP(post, remote)

	loginCtx.timestamp = uint64(time.Now().UnixMilli())
	if loginCtx.loginHexTS == "" {
		loginCtx.loginHexTS = fmt.Sprintf("%016x", loginCtx.timestamp)
	}
	plain := loginCtx.transportPlainPre()
	seq := c.nextMTPSeq()
	mtpPkt := buildMTPAt(session, token, shareKey, shareSign, mtpMsgLogin, seq, 4, plain, loginCtx.nextTransaction(), loginCtx.timestamp)
	kcp := newKCP(session, shareSign)
	kcpPkt := kcp.buildPUSH(mtpPkt)
	Logf("mtp: extra login TX %v sess=%x kcp=%d\n", remote, session, len(kcpPkt))
	if _, err := c.udp.WriteToUDP(kcpPkt, remote); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.udp.SetReadDeadline(time.Now().Add(time.Until(deadline)))
		n, addr, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if addr != nil && !addr.IP.Equal(remote.IP) {
			continue
		}
		pkt := buf[:n]
		if len(pkt) < 40 || !strings.HasPrefix(string(pkt[:4]), "KCP") {
			continue
		}
		_, _, _, payload, ok := parseKCP(pkt)
		if !ok || len(payload) < 48 || string(payload[:4]) != magicMTP {
			continue
		}
		msgID, _, _, enc, err := parseMTP(payload)
		if err != nil || msgID != mtpMsgLoginResp {
			continue
		}
		plain, err := decryptMTPPayload(enc, shareKey)
		if err != nil {
			continue
		}
		eps := parseMediaEndpoints(tlvValue(plain, tlvMediaEndpoints))
		// Per-ssAddr media ChaCha key (LoginResponse 0x0002 ECDH). Required when
		// we later select a relay from this group — primary c.mediaKey is wrong.
		if v := tlvValue(plain, tlvPublicKey); len(v) >= 36 && len(clientPriv) == 32 {
			if mk, err := deriveShareKey(clientPriv, v[4:36]); err == nil {
				for i := range eps {
					eps[i].ShareKey = append([]byte(nil), mk...)
				}
			}
		}
		// Media CNT~ ChaCha uses c.mediaKey (LoginResponse 0x0002 ECDH), not
		// this ssAddr's transport AES shareKey.
		Logf("mtp: extra LoginResponse %v media=%d shareKey=%v\n", remote, len(eps), len(eps) > 0 && len(eps[0].ShareKey) == 32)
		for i, ep := range eps {
			Logf("mtp: extra media[%d] %s:%d sess=%x\n", i, ep.IP, ep.Port, ep.Session)
		}
		// Session-confirm on this side session (msgid=8) so the peer path stays alive.
		if ch := tlvValue(plain, tlvChannelSession); len(ch) == fieldChannelSessionLen {
			reqID := uint32(0)
			if v := tlvValue(plain, tlvRequestID); len(v) >= 4 {
				reqID = binary.BigEndian.Uint32(v[:4])
			}
			loginCtx.timestamp = uint64(time.Now().UnixMilli())
			confPlain := loginCtx.sessionConfirmPlain(ch, reqID)
			confMTP := buildMTPAt(session, token, shareKey, shareSign, mtpMsgSessConfirm, c.nextMTPSeq(), 4, confPlain, loginCtx.nextTransaction(), loginCtx.timestamp)
			_, _ = c.udp.WriteToUDP(kcp.buildPUSH(confMTP), remote)
		}
		c.trackForeignKCP(session, kcp)
		return eps, nil
	}
	return nil, fmt.Errorf("no LoginResponse")
}

func (c *Conn) trackForeignKCP(session []byte, k *kcpState) {
	if c == nil || k == nil || len(session) < 8 {
		return
	}
	var key [8]byte
	copy(key[:], session[:8])
	c.foreignMu.Lock()
	if c.foreignKCP == nil {
		c.foreignKCP = make(map[[8]byte]*kcpState)
	}
	c.foreignKCP[key] = k
	c.foreignMu.Unlock()
	Logf("mtp: tracking extra KCP sess=%x for silent ACK\n", key[:])
}

func (c *Conn) foreignKCPFor(session []byte) *kcpState {
	if len(session) < 8 {
		return nil
	}
	var key [8]byte
	copy(key[:], session[:8])
	c.foreignMu.Lock()
	defer c.foreignMu.Unlock()
	return c.foreignKCP[key]
}

// sendSessionConfirm sends native msgid=8 MSIP after transport login.
func (c *Conn) sendSessionConfirm() error {
	if c.loginCtx == nil {
		return fmt.Errorf("mtp: no login context for session confirm")
	}
	c.loginCtx.timestamp = uint64(time.Now().UnixMilli())
	reqID := c.loginReqID
	if reqID == 0 {
		reqID = c.loginCtx.loginReqID
	}
	plain := c.loginCtx.sessionConfirmPlain(c.channelSession, reqID)
	seq := c.nextMTPSeq()
	txn := c.loginCtx.nextTransaction()
	mtpPkt := buildMTPAt(
		c.session, c.token, c.shareKey, c.signKey, mtpMsgSessConfirm, seq, 4,
		plain, txn, c.loginCtx.timestamp,
	)
	kcpPkt := c.kcp.buildPUSH(mtpPkt)
	Logf("mtp: TX session-confirm msgid=8 seq=%d kcp=%d mtp=%d plain=%d\n",
		seq, len(kcpPkt), len(mtpPkt), len(plain))
	_, err := c.writeUDP(kcpPkt)
	return err
}

// sendDataConnectionReady notifies the camera (via signalling) that the media
// relay path is up — required before video PUSH (pcap msgid=0x17 CSK/SI JSON).
func (c *Conn) sendDataConnectionReady(mediaSess []byte, mediaVA string) error {
	return c.sendDataConnectionReadyVia(nil, mediaSess, mediaVA)
}

// sendDataConnectionReadyVia sends status from the media UDP socket to the
// signalling relay (pcap: :40000 → ssAddr:30005), falling back to c.udp.
func (c *Conn) sendDataConnectionReadyVia(media *net.UDPConn, mediaSess []byte, mediaVA string) error {
	if c.loginCtx == nil {
		return fmt.Errorf("mtp: no login context for DATA_CONNECTION_READY")
	}
	c.loginCtx.timestamp = uint64(time.Now().UnixMilli())
	sigSess := c.channelSession
	if len(sigSess) != 8 {
		sigSess = c.session
	}
	plain := dataConnectionReadyPlain(
		c.loginCtx, sigSess, relayHostPort(c.remote), mediaSess, mediaVA,
	)
	seq := c.nextMTPSeq()
	txn := c.loginCtx.nextTransaction()
	// Wire MTP/KCP session = CNT signalling session; CSK JSON uses 0x001e.
	mtpPkt := buildStatusMTP(c.session, c.token, c.shareKey, c.signKey, mtpMsgStatus, seq, txn, plain)
	kcpPkt := c.kcp.buildPUSH(mtpPkt)
	Logp("mtp: TX DATA_CONNECTION_READY msgid=0x17 seq=%d kcp=%d mtp=%d plain=%d va=%s csk_sess=%x viaMedia=%v\n",
		seq, len(kcpPkt), len(mtpPkt), len(plain), mediaVA, sigSess, media != nil && c.remote != nil)
	return c.writeStatusKCP(media, kcpPkt)
}

func (c *Conn) sendCandidateList(addrs [][]byte) error {
	return c.sendCandidateListVia(nil, addrs)
}

func (c *Conn) sendCandidateListVia(media *net.UDPConn, addrs [][]byte) error {
	if c.loginCtx == nil {
		return fmt.Errorf("mtp: no login context for candidate list")
	}
	c.loginCtx.timestamp = uint64(time.Now().UnixMilli())
	sigSess := c.channelSession
	if len(sigSess) != 8 {
		sigSess = c.session
	}
	// Seed with CNT-mapped addr (NAT port as reported) + local/camera :40000.
	if len(c.loginCtx.relayAddr) == fieldAddrAttrLen {
		addrs = append(addrs, append([]byte(nil), c.loginCtx.relayAddr...))
	}
	if c.localIP != nil {
		addrs = append(addrs, mediaAddrAttr(mediaUDPPort, c.localIP))
	}
	if c.cameraIP != nil {
		addrs = append(addrs, mediaAddrAttr(mediaUDPPort, c.cameraIP))
	}
	// Dedup by full fieldAddrAttrLen-byte value.
	uniq := make([][]byte, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		if len(a) < fieldAddrAttrLen {
			continue
		}
		k := string(a[:fieldAddrAttrLen])
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, a[:20])
	}
	// Native Frida plain≈336 → ~6×20-byte candidates. Pad with media eps.
	for _, ep := range c.mediaEndpoints {
		if len(uniq) >= 6 {
			break
		}
		if ep.IP == nil {
			continue
		}
		a := mediaAddrAttr(ep.Port, ep.IP)
		k := string(a)
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, a)
	}
	plain := candidateListPlain(c.loginCtx, sigSess, uniq)
	seq := c.nextMTPSeq()
	txn := c.loginCtx.nextTransaction()
	mtpPkt := buildStatusMTP(c.session, c.token, c.shareKey, c.signKey, mtpMsgCandidates, seq, txn, plain)
	kcpPkt := c.kcp.buildPUSH(mtpPkt)
	Logf("mtp: TX candidate-list msgid=0x0a seq=%d kcp=%d plain=%d addrs=%d viaMedia=%v\n",
		seq, len(kcpPkt), len(plain), len(uniq), media != nil && c.remote != nil)
	return c.writeStatusKCP(media, kcpPkt)
}

func (c *Conn) sendVideoStartStatus() error {
	return c.sendVideoStartStatusVia(nil)
}

func (c *Conn) sendVideoStartStatusVia(media *net.UDPConn) error {
	if c.loginCtx == nil {
		return nil
	}
	c.loginCtx.timestamp = uint64(time.Now().UnixMilli())
	sigSess := c.channelSession
	if len(sigSess) != 8 {
		sigSess = c.session
	}
	plain := videoStartSentPlain(c.loginCtx, sigSess, relayHostPort(c.remote))
	seq := c.nextMTPSeq()
	txn := c.loginCtx.nextTransaction()
	mtpPkt := buildStatusMTP(c.session, c.token, c.shareKey, c.signKey, mtpMsgStatus, seq, txn, plain)
	kcpPkt := c.kcp.buildPUSH(mtpPkt)
	Logp("mtp: TX VIDEO_START_SEND msgid=0x17 seq=%d kcp=%d plain=%d viaMedia=%v\n",
		seq, len(kcpPkt), len(plain), media != nil && c.remote != nil)
	return c.writeStatusKCP(media, kcpPkt)
}

func (c *Conn) writeStatusKCP(media *net.UDPConn, kcpPkt []byte) error {
	if media != nil && c.remote != nil {
		_, err := media.WriteToUDP(kcpPkt, c.remote)
		return err
	}
	_, err := c.writeUDP(kcpPkt)
	return err
}

func (c *Conn) pushAuthSuccess() {
	body := []byte(`{"result":"success"}`)
	buf := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(buf[0:4], 0x101)
	copy(buf[4:], body)
	c.channels.cmd.Push(buf)
}

func (c *Conn) nextMTPSeq() uint32 {
	return atomic.AddUint32(&c.mtpSeq, 1)
}

func (c *Conn) worker() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-c.closed:
			return
		default:
		}
		if dl, ok := c.deadline.Load().(time.Time); ok && !dl.IsZero() {
			_ = c.udp.SetReadDeadline(dl)
		} else {
			_ = c.udp.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
		n, addr, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			c.setErr(err)
			return
		}
		c.handlePacket(buf[:n], addr)
	}
}

func (c *Conn) handlePacket(pkt []byte, from *net.UDPAddr) {
	if len(pkt) < 4 {
		return
	}
	magic := string(pkt[0:4])
	// Media path (CNT~ / KCP~) shares the same :40000 socket.
	if magic == "CNT~" {
		if ms := c.mediaSess.Load(); ms != nil && ms.bound.Load() {
			ms.handleCNT(pkt)
			return
		}
		if ch := c.mediaRX; ch != nil {
			cp := append([]byte(nil), pkt...)
			select {
			case ch <- cp:
			default:
				Logf("mtp: mediaRX full, drop CNT~ len=%d\n", len(pkt))
			}
			return
		}
	}
	if magic == magicKCPt {
		if ms := c.mediaSess.Load(); ms != nil {
			Logf("mtp: RX KCP~ len=%d sess=%x → media\n", len(pkt), pkt[4:min(12, len(pkt))])
			if ms.rdtListen.Load() {
				// Logf above is invisible under mtp_verbose:false (the deployed
				// config), and rdtTaggedRX only counts frames that reach CHK
				// classification inside handleCHK — this fires for every raw
				// datagram the worker hands to this media session while an RDT
				// fetch is in progress, regardless of session/magic/parse
				// outcome, so a stall can be told apart from "camera genuinely
				// stopped sending" vs. "something between here and CHK
				// classification (foreign-session filter, KCP parse) is
				// dropping packets that did arrive". ms.loop() (the other
				// consumer of ms.handle) is dead code — this is the only path
				// that actually runs.
				n := ms.rdtRawRX.Add(1)
				// Sampled coarsely (every 200th, not every 20th): the
				// multi-fragment RDT fix (2026-08-03) means a healthy fetch
				// now completes in ~130 frames instead of stalling for
				// hundreds, so dense per-packet sampling here was chewing
				// through the container's log rotation budget (max-size 20m
				// x max-file 5) fast enough to lose other diagnostics within
				// tens of minutes — this is now background health signal,
				// not the primary debugging tool it was while the fetch was
				// still broken.
				if n == 1 || n%200 == 0 {
					Logp("mtp: media raw RX during RDT fetch len=%d head=%x (count=%d)\n",
						len(pkt), pkt[:min(16, len(pkt))], n)
				}
			}
			ms.handle(pkt)
			return
		}
		if ch := c.mediaRX; ch != nil {
			cp := append([]byte(nil), pkt...)
			select {
			case ch <- cp:
			default:
			}
			return
		}
		Logf("mtp: RX KCP~ len=%d (no media session yet)\n", len(pkt))
	}
	Logf("mtp: RX len=%d magic=%q head=%x\n", len(pkt), magic, pkt[:min(32, len(pkt))])
	switch {
	case magic == magicCNT || magic == magicLAN:
		if len(pkt) >= 36 {
			Logf("mtp: RX CNT sess=%x msgid=%d blen=%d bodyType=%d\n",
				pkt[4:12],
				binary.BigEndian.Uint16(pkt[12:14]),
				binary.BigEndian.Uint16(pkt[14:16]),
				binary.BigEndian.Uint32(pkt[32:36]))
		}
		return
	case strings.HasPrefix(magic, "KCP"):
		// Extra-ssAddr logins share this UDP socket with different CNT sessions.
		// ACK them (correct PacketSign) so servers stop retransmitting; never
		// decrypt under the primary shareKey.
		if len(c.session) >= 8 && len(pkt) >= 12 && !bytes.Equal(pkt[4:12], c.session[:8]) {
			c.handleForeignKCP(pkt, from)
			return
		}
		cmd, sn, una, payload, ok := parseKCP(pkt)
		if !ok {
			Logf("mtp: RX KCP parse fail\n")
			return
		}
		atomic.StoreUint32(&c.kcp.una, una)
		if cmd == kcpCmdACK {
			Logf("mtp: RX KCP ACK sn=%d una=%d\n", sn, una)
			return
		}
		if cmd == kcpCmdPush {
			Logf("mtp: RX KCP PUSH sn=%d una=%d pay=%d\n", sn, una, len(payload))
			_, _ = c.writeUDP(c.kcp.buildACK(sn, sn+1))
			c.handleInner(payload)
		}
	default:
		c.handleInner(pkt)
	}
}

func (c *Conn) handleForeignKCP(pkt []byte, from *net.UDPAddr) {
	sess := pkt[4:12]
	cmd, sn, _, _, ok := parseKCP(pkt)
	if !ok {
		return
	}
	if fk := c.foreignKCPFor(sess); fk != nil && cmd == kcpCmdPush {
		ack := fk.buildACK(sn, sn+1)
		if from != nil {
			_, _ = c.udp.WriteToUDP(ack, from)
		} else {
			_, _ = c.writeUDP(ack)
		}
		return
	}
	key := fmt.Sprintf("%x", sess)
	if _, seen := c.foreignLog.LoadOrStore(key, true); !seen {
		Logf("mtp: RX KCP foreign sess=%x (ours=%x), ignore+ACK if tracked\n",
			sess, c.session[:min(8, len(c.session))])
	}
}

func (c *Conn) handleInner(payload []byte) {
	if len(payload) < 4 {
		return
	}
	switch string(payload[0:3]) {
	case "MTP":
		if len(c.session) >= 8 && len(payload) >= 12 && !bytes.Equal(payload[4:12], c.session[:8]) {
			Logf("mtp: RX MTP foreign sess=%x, ignore\n", payload[4:12])
			return
		}
		msgID, seq, token, enc, err := parseMTP(payload)
		if err != nil {
			Logf("mtp: parse MTP: %v\n", err)
			return
		}
		plain, err := decryptMTPPayload(enc, c.shareKey)
		if err != nil {
			Logf("mtp: decrypt msgid=%d seq=%d: %v\n", msgID, seq, err)
			return
		}
		if len(token) == 16 {
			c.token = token
		}
		Logf("mtp: RX MTP msgid=%d seq=%d plain=%d head=%x\n",
			msgID, seq, len(plain), plain[:min(32, len(plain))])
		if cmd, data, err := decodeMissCommand(plain); err == nil && cmd >= 0x100 && cmd < 0x2000 {
			Logf("mtp: RX miss cmd=0x%x len=%d\n", cmd, len(data))
			buf := make([]byte, 4+len(data))
			binary.LittleEndian.PutUint32(buf[0:4], cmd)
			copy(buf[4:], data)
			c.channels.cmd.Push(buf)
			return
		}
		if msgID == mtpMsgSessAck {
			Logf("mtp: RX session-confirm ACK (msgid=12)\n")
		}
		c.scanMissCommands(plain)
	case "CHK":
		// Media frames arrive on the dedicated media UDP session (media_kcp.go).
	}
}

func (c *Conn) scanMissCommands(body []byte) {
	if strings.Contains(string(body), `"result"`) || bytes.Contains(body, []byte(`"RSLT"`)) {
		buf := make([]byte, 4+len(body))
		binary.LittleEndian.PutUint32(buf[0:4], 0x101)
		copy(buf[4:], body)
		c.channels.cmd.Push(buf)
	}
}

func (c *Conn) setErr(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

func (c *Conn) Error() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

func (c *Conn) Protocol() string { return "mtp" }

func (c *Conn) Version() string {
	if c.ssVer != "" {
		return c.ssVer
	}
	return "mtp"
}

func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadline.Store(t)
	return nil
}

// DrainMedia drops queued media frames (e.g. live leftovers before SD playback).
func (c *Conn) DrainMedia() int {
	if c.channels == nil || c.channels.media == nil {
		return 0
	}
	return c.channels.media.Drain()
}

// DrainCommands drops queued miss control responses.
func (c *Conn) DrainCommands() int {
	if c.channels == nil || c.channels.cmd == nil {
		return 0
	}
	return c.channels.cmd.Drain()
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.udp.Close()
	})
	return nil
}

// Alive is true while the UDP session has not failed or been closed.
func (c *Conn) Alive() bool {
	if c == nil {
		return false
	}
	if c.Error() != nil {
		return false
	}
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

// ReadCommandUntil waits for one miss control cmd until deadline without
// touching the shared UDP read deadline (unlike SetDeadline + ReadCommand).
func (c *Conn) ReadCommandUntil(deadline time.Time) (cmd uint32, data []byte, err error) {
	if c.channels == nil || c.channels.cmd == nil {
		return 0, nil, fmt.Errorf("mtp: no cmd channel")
	}
	buf, err := c.channels.cmd.PopWait(deadline)
	if err != nil {
		return 0, nil, err
	}
	if len(buf) < 4 {
		return 0, nil, fmt.Errorf("mtp: short cmd")
	}
	return binary.LittleEndian.Uint32(buf[0:4]), buf[4:], nil
}

func (c *Conn) ReadCommand() (cmd uint32, data []byte, err error) {
	deadline, _ := c.deadline.Load().(time.Time)
	buf, err := c.channels.cmd.PopWait(deadline)
	if err != nil {
		if e := c.Error(); e != nil {
			return 0, nil, e
		}
		return 0, nil, err
	}
	cmd = binary.LittleEndian.Uint32(buf[0:4])
	data = buf[4:]
	return cmd, data, nil
}

func (c *Conn) WriteCommand(cmd uint32, data []byte) error {
	// Vendor-6 native path has no MISS JSON 0x100 over MTP — transport LoginResponse
	// is the auth. Send msgid=8 session-confirm and synthesize auth success for miss.login.
	if cmd == 0x100 {
		if !c.appAuthed.Swap(true) {
			if err := c.sendSessionConfirm(); err != nil {
				return err
			}
			c.pushAuthSuccess()
			Logp("mtp: app auth via transport login (skipped JSON 0x100)\n")
		}
		return nil
	}
	// VIDEO_START / stream cmds ride on media KCP~/CHK~ via WriteMediaCommand.
	// Encrypted Client.WriteCommand(0x1001) is the CS2 path — ignore on MTP.
	if cmd == 0x1001 {
		Logf("mtp: skip signalling 0x1001 (%d B); use WriteMediaCommand for stream cmds\n", len(data))
		return nil
	}

	payload := encodeMissCommand(cmd, data)
	msgID := mtpMsgStatus
	typ := uint32(16)
	seq := c.nextMTPSeq()
	mtpPkt := buildMTP(c.session, c.token, c.shareKey, c.signKey, msgID, seq, typ, payload)
	kcpPkt := c.kcp.buildPUSH(mtpPkt)

	var wire []byte
	if len(c.pendingCNT) > 0 {
		wire = append(c.pendingCNT, kcpPkt...)
		c.pendingCNT = nil
		Logf("mtp: TX coalesced CNT+KCP total=%d (mtp cmd=0x%x msgid=%d seq=%d plain=%d mtp=%d)\n",
			len(wire), cmd, msgID, seq, len(payload), len(mtpPkt))
	} else {
		wire = kcpPkt
		Logf("mtp: TX miss cmd=0x%x msgid=%d seq=%d plain=%d mtp=%d\n", cmd, msgID, seq, len(payload), len(mtpPkt))
	}
	_, err := c.writeUDP(wire)
	return err
}

func (c *Conn) ReadPacket() (hdr, payload []byte, err error) {
	deadline, _ := c.deadline.Load().(time.Time)
	buf, err := c.channels.media.PopWait(deadline)
	if err != nil {
		if e := c.Error(); e != nil {
			return nil, nil, e
		}
		return nil, nil, err
	}
	const hdrSize = 32
	if len(buf) < hdrSize {
		hdr = make([]byte, hdrSize)
		return hdr, buf, nil
	}
	return buf[:hdrSize], buf[hdrSize:], nil
}

func (c *Conn) WritePacket(hdr, payload []byte) error {
	buf := append(append([]byte(nil), hdr...), payload...)
	seq := c.nextMTPSeq()
	mtpPkt := buildMTP(c.session, c.token, c.shareKey, c.signKey, mtpMsgStatus, seq, 16, buf)
	_, err := c.writeUDP(c.kcp.buildPUSH(mtpPkt))
	return err
}

// WriteMediaCommand sends a clear miss cmd on the bound media KCP~/CHK~ session.
func (c *Conn) WriteMediaCommand(cmd uint32, json []byte) error {
	if err := c.WaitMediaReady(45 * time.Second); err != nil {
		return err
	}
	ms := c.mediaSess.Load()
	if ms == nil {
		return fmt.Errorf("mtp: no media session")
	}
	return ms.sendCommand(cmd, string(json))
}

// WaitMediaReady blocks until media bind+bootstrap finished and CHK/video is
// proven. bindOK alone is not enough — RDT/playback need a live miss path.
func (c *Conn) WaitMediaReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := c.Error(); err != nil {
			return err
		}
		select {
		case <-c.closed:
			return fmt.Errorf("mtp: closed")
		default:
		}
		ms := c.mediaSess.Load()
		if ms != nil && ms.bound.Load() && ms.bootOK.Load() &&
			(ms.gotVideo.Load() || ms.chkAlive.Load()) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("mtp: media session not ready")
}

// WaitMediaCmdReady blocks until miss CHK commands are proven alive (ctrl or
// video). SD 0x10d must not run on bind-only sessions that never got 0x113.
func (c *Conn) WaitMediaCmdReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := c.Error(); err != nil {
			return err
		}
		select {
		case <-c.closed:
			return fmt.Errorf("mtp: closed")
		default:
		}
		ms := c.mediaSess.Load()
		if ms != nil && ms.bound.Load() && ms.bootOK.Load() &&
			(ms.gotVideo.Load() || ms.chkAlive.Load()) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("mtp: media chk not alive")
}

// WaitMediaVideo waits until at least one live media frame arrived (best-effort).
// RDT type-6 is much more reliable once KCP recv UNA has climbed with video.
func (c *Conn) WaitMediaVideo(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-c.closed:
			return false
		default:
		}
		ms := c.mediaSess.Load()
		if ms != nil && ms.gotVideo.Load() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// NudgeMediaStream re-sends live start commands when bind succeeded but CHK/video
// never arrived (common relay stall before RDT).
func (c *Conn) NudgeMediaStream() error {
	ms := c.mediaSess.Load()
	if ms == nil || !ms.bound.Load() {
		return fmt.Errorf("mtp: no media session to nudge")
	}
	Logp("mtp: nudge media stream (0x102/0x109/0x104 + VIDEO_START)\n")
	_ = ms.sendCommand(0x102, `{}`)
	time.Sleep(200 * time.Millisecond)
	_ = ms.sendCommand(0x109, `{"videoquality":0}`)
	time.Sleep(200 * time.Millisecond)
	_ = ms.sendCommand(0x104, `{}`)
	time.Sleep(200 * time.Millisecond)
	return c.sendVideoStartStatusVia(nil)
}
