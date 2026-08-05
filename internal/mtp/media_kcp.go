package mtp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	chkHdrSize       = 36
	mediaKCPSignLen  = 88 // ServerSign window for KCP~+CHK~ (pcap)
	mediaPacketSignN = 52 // PacketSign trailer length field (pcap)
	chkCtrlFlag      = 0xc000
	chkModeCtrl      = 0
	chkModeRDT       = 1

	// rdtMaxSingleFrameSize bounds what pushRDTOrMedia accepts into the RDT
	// queue as one deliverable. Real captures show ~2 KB per type-6 callback;
	// 8 KB gives ample margin for larger implicit chunks while still
	// rejecting a misclassified multi-fragment video frame (observed live at
	// 245 KB) that would otherwise blow through rdtRawHardCap in one append.
	rdtMaxSingleFrameSize = 8192
)

// mediaSession is one UDP media relay (CNT~ bind + KCP~/CHK~ stream).
type mediaSession struct {
	conn     *net.UDPConn
	remote   *net.UDPAddr // set when using unconnected ListenUDP
	session  []byte
	ep       mediaEndpoint // selected relay for post-bind CNT~ answers
	shareKey []byte
	authSign []byte // HMAC(authToken, authToken) for media ServerSign
	signKey  []byte // HMAC(share, share) — PacketSign attempt
	kcp      *kcpState
	chkSeq    uint32
	chkSeqRDT uint32 // channel-3 RDT CHK seq (native: independent of miss-cmd seq)
	ackPad    uint32 // native media ACK pad byte at [32], starts 0x0b
	cntSeq    uint32 // media CNT~ seq after bind
	parent    *Conn

	// video reassembly: frag index → plaintext chunk (first holds miss hdr)
	frameSeq  uint32
	frameNeed uint16
	frags     map[uint16][]byte
	gotVideo  atomic.Bool
	chkAlive  atomic.Bool // true after any RX CHK~ ctrl/media (path is live)
	bound     atomic.Bool // true once bind dance finished; CNT~ → handleCNT
	bootOK    atomic.Bool // true after sendBootstrap finished
	bindOK    atomic.Bool // true after punch2/716 (not incomplete fallback)
	last13    atomic.Int64 // unix nano of last TX 0x13 (debounce)
	rdtListen atomic.Bool  // route non-video CHK frames to RDT queue
	needKey   atomic.Bool  // drop P-frames until next IRAP after loss
	// rdtTaggedRX counts CHK frames classified as RDT-tagged (0xd8/0x58, or an
	// accepted 0x50) regardless of rdtListen — lets FetchTimelineIndex report
	// whether the camera sent any type-6 traffic at all during a fetch,
	// distinguishing "camera never answered" from "we dropped what arrived".
	rdtTaggedRX atomic.Uint64
	// foreignSessionRX counts KCP~ packets dropped by sessionMatches — see
	// handle()'s doc comment. Logged at a rate limit (first + every 100th)
	// since extra media endpoints can keep sending continuously.
	foreignSessionRX atomic.Uint64
	// rdtRawRX counts every raw UDP datagram seen by loop() while rdtListen is
	// set, regardless of session/magic/type — see loop()'s doc comment.
	rdtRawRX atomic.Uint64

	// KCP recv tracking for media ACKs.
	ackMu         sync.Mutex
	rcvNext       uint32
	rcvMax        uint32
	recvInit      bool
	recvBuf       map[uint32]struct{}
	ackPending    []uint32  // sn's queued for the next batched ACK (RDT fetch only)
	ackBatchStart time.Time
	holeSince time.Time
}

func (ms *mediaSession) write(pkt []byte) (int, error) {
	if ms.remote != nil {
		return ms.conn.WriteToUDP(pkt, ms.remote)
	}
	return ms.conn.Write(pkt)
}

func (c *Conn) startMediaProbes() {
	if c.mediaStarted.Swap(true) {
		return
	}
	eps := append([]mediaEndpoint(nil), c.mediaEndpoints...)
	if len(eps) == 0 {
		Logp("mtp: no media endpoints in LoginResponse; skipping CNT~\n")
		return
	}
	go func() {
		if err := c.runMediaBind(eps); err != nil {
			Logp("mtp: media bind: %v\n", err)
		}
	}()
}

func (c *Conn) runMediaBind(eps []mediaEndpoint) error {
	// Native: one UDP :40000 for signalling + media. Reuse c.udp; demux CNT~
	// via c.mediaRX while the worker owns ReadFromUDP.
	conn := c.udp
	if conn == nil {
		return fmt.Errorf("mtp: no UDP for media bind")
	}
	mediaRX := make(chan []byte, 64)
	c.mediaRX = mediaRX
	defer func() { c.mediaRX = nil }()

	if c.localIP == nil {
		if d, err := net.Dial("udp", net.JoinHostPort(eps[0].IP.String(), "9")); err == nil {
			if la, ok := d.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
				c.localIP = la.IP.To4()
			}
			_ = d.Close()
		}
	}
	if c.cameraIP == nil {
		c.cameraIP = c.localIP
	}
	Logp("mtp: media bind local=%v camera=%v cnt-relay=%x eps=%d sock=%v\n",
		c.localIP, c.cameraIP, c.loginCtx.relayAddr, len(eps), conn.LocalAddr())

	// MediaBinding/CNT| 0x0015 stays LoginResponse buddy (pcap 93.84:…), not
	// STUN XOR-MAPPED. Skip STUN when buddy is already known — discoverBuddyAddr
	// races the worker on the shared UDP socket and delays the punch wave.
	haveBuddy := c.loginCtx != nil && len(c.loginCtx.buddyAddr) >= 8
	if !haveBuddy {
		var stunExtra []string
		if c.loginCtx != nil {
			stunExtra = parseStunAddrList(c.loginCtx.stunAddrs)
		}
		if mapped, err := discoverBuddyAddr(conn, stunExtra...); err == nil {
			c.loginCtx.buddyAddr = mapped
			Logf("mtp: buddy 0x0015 from STUN fallback %v:%d\n",
				net.IP(mapped[4:8]), binary.BigEndian.Uint16(mapped[2:4]))
		} else {
			Logp("mtp: STUN NAT probe failed: %v\n", err)
		}
	}
	if c.loginCtx != nil && len(c.loginCtx.buddyAddr) >= 8 {
		b := c.loginCtx.buddyAddr
		Logf("mtp: using buddy 0x0015 %v:%d for MediaBinding/CNT|\n",
			net.IP(b[4:8]), binary.BigEndian.Uint16(b[2:4]))
	}

	// Native keeps 0x0020=3 (per LoginResponse group), even when punching 9 eps.
	count := uint32(3)
	if n := uint32(len(eps)); n > 0 && n < 3 {
		count = n
	}
	// Native: per-session monotonic seq (1,2,3…) — never reuse across 0x11+0x10 pair.
	sessSeq := map[string]uint32{}
	nextSeq := func(ep mediaEndpoint) uint32 {
		k := string(ep.Session)
		sessSeq[k]++
		return sessSeq[k]
	}
	writeCNTFull := func(ep mediaEndpoint, msgID uint16, echoToken []byte, echoTxn uint32) error {
		if c.loginCtx != nil {
			c.loginCtx.timestamp = uint64(time.Now().UnixMilli())
		}
		txn := echoTxn
		if txn == 0 {
			txn = uint32(0x008bc500)
			if c.loginCtx != nil {
				txn = c.loginCtx.nextTransaction()
			}
		}
		sk := c.mediaShareKey()
		if len(ep.ShareKey) == 32 {
			sk = ep.ShareKey
		}
		seq := nextSeq(ep)
		pkt := buildMediaCNTMsg(
			ep, c.loginCtx, sk, []byte(c.authTok),
			c.localIP, c.cameraIP, count, seq, txn, msgID, echoToken,
		)
		addr := &net.UDPAddr{IP: ep.IP, Port: int(ep.Port)}
		if _, err := conn.WriteToUDP(pkt, addr); err != nil {
			return fmt.Errorf("CNT~ TX msgid=%#x: %w", msgID, err)
		}
		Logf("mtp: TX CNT~ msgid=%#x %s sess=%x seq=%d txn=%#x len=%d\n",
			msgID, addr, ep.Session, seq, txn, len(pkt))
		if msgID == cntMsgReply || msgID == cntMsgBound {
			if m, err := parseMediaCNT(pkt); err == nil {
				_ = m.decrypt(sk)
				a15 := m.TLVs[tlvMappedAddr]
				a2c := m.TLVs[tlvBuddyFlag]
				port := uint16(0)
				var ip net.IP
				if len(a15) >= 8 {
					port = binary.BigEndian.Uint16(a15[2:4])
					ip = net.IP(a15[4:8])
				}
				Logf("mtp: TX clear 13/14/15=%v/%v/%v:%d 2c=%x plain2f=%x\n",
					net.IP(m.TLVs[tlvLocalAddr][4:8]), net.IP(m.TLVs[tlvCameraAddr][4:8]),
					ip, port, a2c, tlvValue(m.Plain, tlvBindingFlag))
			}
		}
		return nil
	}
	writeCNT := func(ep mediaEndpoint, msgID uint16, echoToken []byte) error {
		return writeCNTFull(ep, msgID, echoToken, 0)
	}

	mappedAddrs := make([][]byte, 0, 8)
	var punchMapped []byte // server-echo 0x0015 from punch-ack (≠ native buddy)
	collectMapped := func(pkt []byte) {
		if a := extractMappedAddr(pkt); len(a) == fieldAddrAttrLen {
			mappedAddrs = append(mappedAddrs, a)
			if (a[4] | a[5] | a[6] | a[7]) != 0 {
				punchMapped = append([]byte(nil), a...)
				Logf("mtp: server-echo 0x0015 %v:%d (from CNT~ clear)\n",
					net.IP(a[4:8]), binary.BigEndian.Uint16(a[2:4]))
				// Never overwrite LoginResponse/STUN buddy with punch-ack echo.
				if c.loginCtx != nil && len(c.loginCtx.buddyAddr) < 8 {
					c.loginCtx.buddyAddr = append([]byte(nil), a...)
					Logf("mtp: buddy 0x0015 from punch-ack fallback %v:%d\n",
						net.IP(a[4:8]), binary.BigEndian.Uint16(a[2:4]))
				}
			}
		}
	}
	findEP := func(sess []byte) (mediaEndpoint, bool) {
		for _, ep := range eps {
			if len(sess) >= 8 && len(ep.Session) >= 8 {
				same := bytes.Equal(ep.Session, sess[:8])
				flip := (ep.Session[0]^0x80) == sess[0] && bytes.Equal(ep.Session[1:8], sess[1:8])
				if same || flip {
					return ep, true
				}
			}
		}
		return mediaEndpoint{}, false
	}
	pendingCNT := make([]*mediaCNT, 0, 16)
	pendingEP := make([]mediaEndpoint, 0, 16)
	waitAny := func(timeout time.Duration, prefer *mediaEndpoint, pred func(m *mediaCNT, ep mediaEndpoint) bool) (mediaEndpoint, *mediaCNT, error) {
		// Drain stashed frames first (e.g. server 0x10 that arrived during ACK wait).
		for i := 0; i < len(pendingCNT); {
			m := pendingCNT[i]
			ep := pendingEP[i]
			if prefer != nil && !bytes.Equal(prefer.Session, ep.Session) {
				i++
				continue
			}
			if pred(m, ep) {
				pendingCNT = append(pendingCNT[:i], pendingCNT[i+1:]...)
				pendingEP = append(pendingEP[:i], pendingEP[i+1:]...)
				return ep, m, nil
			}
			i++
		}
		deadline := time.NewTimer(timeout)
		defer deadline.Stop()
		for {
			select {
			case <-deadline.C:
				return mediaEndpoint{}, nil, fmt.Errorf("i/o timeout")
			case pkt := <-mediaRX:
				if len(pkt) < 14 || string(pkt[:4]) != "CNT~" {
					continue
				}
				collectMapped(pkt)
				m, err := parseMediaCNT(pkt)
				if err != nil {
					Logf("mtp: RX CNT~ parse err: %v len=%d\n", err, len(pkt))
					continue
				}
				sk := c.mediaShareKey()
				ep, ok := findEP(m.Session)
				if ok && len(ep.ShareKey) == 32 {
					sk = ep.ShareKey
				}
				_ = m.decrypt(sk)
				if len(m.Plain) == 0 && len(m.Blob) >= 8 {
					for _, e2 := range eps {
						if len(e2.ShareKey) == 32 && m.decrypt(e2.ShareKey) {
							Logf("mtp: RX CNT~ decrypted via ep.ShareKey sess=%x\n", e2.Session)
							break
						}
					}
					if len(m.Plain) == 0 && m.decrypt(c.shareKey) {
						Logf("mtp: RX CNT~ decrypted via transport shareKey\n")
					}
				}
				Logf("mtp: RX CNT~ %s sess=%x\n", m.summary(), m.Session)
				if !ok {
					continue
				}
				if prefer != nil && !bytes.Equal(prefer.Session, ep.Session) {
					pendingCNT = append(pendingCNT, m)
					pendingEP = append(pendingEP, ep)
					continue
				}
				if pred(m, ep) {
					return ep, m, nil
				}
				// Keep server punch/binding frames for the next wait stage.
				if m.Kind == cntKindPunch || m.Kind == cntKindBinding || m.Kind == cntKindBound {
					pendingCNT = append(pendingCNT, m)
					pendingEP = append(pendingEP, ep)
				}
			}
		}
	}

	chanSess := c.channelSession
	if len(chanSess) != 8 {
		chanSess = c.session
	}
	sendLAN := func(magic string, dst *net.UDPAddr, epCount uint32) {
		if dst == nil || c.loginCtx == nil {
			return
		}
		txn := c.loginCtx.nextTransaction()
		pkt := buildLANPunchCNT(magic, chanSess, c.loginCtx, c.mediaShareKey(), c.localIP, c.cameraIP, epCount, 1, txn)
		if len(pkt) == 0 {
			return
		}
		if _, err := conn.WriteToUDP(pkt, dst); err != nil {
			Logf("mtp: LAN %q TX: %v\n", magic, err)
			return
		}
		Logf("mtp: TX LAN %q %v sess=%x len=%d\n", magic, dst, chanSess, len(pkt))
	}
	// CNT| targets the same self-map advertised in MediaBinding 0x0015.
	// Native re-sends these throughout the bind (pcap: 17× to self-map).
	sendSelfMapPunch := func() {
		pub := c.loginCtx.buddyAddr
		if len(pub) < 8 {
			pub = c.loginCtx.relayAddr
		}
		if len(pub) < 8 {
			return
		}
		if v4 := net.IP(pub[4:8]).To4(); v4 != nil && !isZero(v4) {
			p := mediaUDPPort
			if mp := int(binary.BigEndian.Uint16(pub[2:4])); mp != 0 {
				p = mp
			}
			sendLAN("CNT|", &net.UDPAddr{IP: v4, Port: p}, 2)
		}
	}
	if c.cameraIP != nil {
		cam := &net.UDPAddr{IP: c.cameraIP, Port: mediaUDPPort}
		sendLAN("CNT\x00", cam, 1)
		sendLAN("CNT\x01", cam, 1)
	}
	sendSelfMapPunch()
	nextSelfMapPunch := time.Now().Add(200 * time.Millisecond)

	for _, ep := range eps {
		if err := writeCNT(ep, cntMsgPunch, nil); err != nil {
			return err
		}
	}
	acked := map[string]mediaEndpoint{}
	ackDeadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(ackDeadline) {
		ep, _, err := waitAny(time.Until(ackDeadline), nil, func(m *mediaCNT, _ mediaEndpoint) bool {
			return m.Kind == cntKindPunchACK || (m.MsgID == cntMsgReply && m.Kind != cntKindBinding)
		})
		if err != nil {
			break
		}
		acked[string(ep.Session)] = ep
	}
	if len(acked) == 0 {
		return fmt.Errorf("media punch: no 0x11 ACKs")
	}
	for _, ep := range eps {
		_ = writeCNT(ep, cntMsgPunch, nil)
	}
	Logp("mtp: media punch ACKs=%d; waiting for server punch/binding\n", len(acked))

	// Fresh pcap + Frida MediaBinding procs:
	//   S punch 0x10 → C MediaBinding reply 0x11 + punch 0x10
	//   S punch2 0x12 → C bound 0x13 + punch2 0x12
	//   S binding/bound 716 = ReceivedMediaBindingResponse (after 0x13)
	// Some paths never send S punch; after a short wait we MediaBinding every
	// acked primary endpoint ourselves (client-initiated bind).
	answered := map[string]bool{}
	var selected mediaEndpoint
	got12 := false
	var ep mediaEndpoint
	epIndex := func(e mediaEndpoint) int {
		for i, x := range eps {
			if bytes.Equal(x.Session, e.Session) {
				return i
			}
		}
		return len(eps) + 1
	}
	pickBetter := func(cur, cand mediaEndpoint) mediaEndpoint {
		if cur.IP == nil {
			return cand
		}
		if epIndex(cand) < epIndex(cur) {
			return cand
		}
		return cur
	}
	proactiveAt := time.Now().Add(1500 * time.Millisecond)
	proactiveDone := false
	waitEnd := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitEnd) {
		if time.Now().After(nextSelfMapPunch) {
			sendSelfMapPunch()
			nextSelfMapPunch = time.Now().Add(350 * time.Millisecond)
		}
		if !proactiveDone && time.Now().After(proactiveAt) && len(answered) == 0 {
			proactiveDone = true
			Logp("mtp: no server punch yet — proactive MediaBinding on acked eps\n")
			for _, e := range eps {
				if _, ok := acked[string(e.Session)]; !ok {
					continue
				}
				_ = writeCNT(e, cntMsgReply, nil)
				_ = writeCNT(e, cntMsgPunch, nil)
				answered[string(e.Session)] = true
				selected = pickBetter(selected, e)
			}
		}
		var m *mediaCNT
		var err error
		slice := 200 * time.Millisecond
		if rem := time.Until(waitEnd); rem < slice {
			slice = rem
		}
		if slice <= 0 {
			break
		}
		ep, m, err = waitAny(slice, nil, func(m *mediaCNT, ep mediaEndpoint) bool {
			key := string(ep.Session)
			if m.MsgID == cntMsgPunch && m.Kind == cntKindPunch && !answered[key] {
				return true
			}
			if m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch {
				return true
			}
			return m.Kind == cntKindBinding || m.Kind == cntKindBound
		})
		if err != nil {
			continue
		}
		switch {
		case m.MsgID == cntMsgPunch && m.Kind == cntKindPunch:
			if answered[string(ep.Session)] {
				continue
			}
			Logp("mtp: got server punch %s — TX MediaBinding+punch\n", m.summary())
			if c.loginCtx != nil {
				ba := c.loginCtx.buddyAddr
				if len(ba) < 8 {
					ba = c.loginCtx.relayAddr
				}
				if len(ba) >= 8 {
					Logf("mtp: buddy 0x0015 %v:%d (self-map; punch-ack=%v)\n",
						net.IP(ba[4:8]), binary.BigEndian.Uint16(ba[2:4]),
						len(punchMapped) >= 8)
				}
			}
			if err := writeCNT(ep, cntMsgReply, nil); err != nil {
				return err
			}
			if err := writeCNT(ep, cntMsgPunch, nil); err != nil {
				return err
			}
			answered[string(ep.Session)] = true
			selected = pickBetter(selected, ep)
		case m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch:
			Logp("mtp: got server punch2 %s — TX bound+punch2\n", m.summary())
			echoTxn := uint32(0)
			if v := m.TLVs[tlvTransactionID]; len(v) >= 4 {
				echoTxn = binary.BigEndian.Uint32(v[:4])
			}
			if err := writeCNTFull(ep, cntMsgBound, m.Token, echoTxn); err != nil {
				return err
			}
			if err := writeCNT(ep, cntMsgPunch2, nil); err != nil {
				return err
			}
			selected = pickBetter(selected, ep)
			got12 = true
		case m.Kind == cntKindBinding || m.Kind == cntKindBound:
			if !answered[string(ep.Session)] && selected.IP != nil {
				Logf("mtp: ignore server %s on unanswered sess=%x\n", m.kindName(), ep.Session)
				continue
			}
			Logp("mtp: got server %s (MediaBinding response) — bind ready\n", m.summary())
			if len(m.Plain) > 0 {
				Logf("mtp: binding plain tlvs=%s\n", summarizeTLVs(m.Plain))
			}
			if !got12 {
				Logf("mtp: no punch2 yet — TX bound to complete dance\n")
				_ = writeCNT(ep, cntMsgBound, nil)
				_ = writeCNT(ep, cntMsgPunch2, nil)
			}
			selected = ep
			got12 = true
			goto bindDone
		}
	}
	if selected.IP == nil {
		for _, e := range eps {
			if _, ok := acked[string(e.Session)]; ok {
				selected = e
				break
			}
		}
		Logp("mtp: no server punch; probing selected %s:%d sess=%x\n",
			selected.IP, selected.Port, selected.Session)
		_ = writeCNT(selected, cntMsgReply, nil)
		_ = writeCNT(selected, cntMsgPunch, nil)
		answered[string(selected.Session)] = true
	} else {
		// Prefer earliest LoginResponse endpoint among those we MediaBinding'd.
		for _, e := range eps {
			if answered[string(e.Session)] {
				selected = e
				break
			}
		}
	}
	ep = selected
	Logp("mtp: media selected %s:%d sess=%x answered=%d got12=%v\n",
		ep.IP, ep.Port, ep.Session, len(answered), got12)

	// Brief wait for late punch2 / MediaBinding response 716.
	if got12 {
		waitResp := time.Now().Add(2 * time.Second)
		for time.Now().Before(waitResp) {
			e2, m, err := waitAny(time.Until(waitResp), nil, func(m *mediaCNT, _ mediaEndpoint) bool {
				return m.Kind == cntKindBinding || m.Kind == cntKindBound ||
					(m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch)
			})
			if err != nil {
				break
			}
			ep = e2
			if m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch {
				Logp("mtp: late server punch2 — TX bound\n")
				echoTxn := uint32(0)
				if v := m.TLVs[tlvTransactionID]; len(v) >= 4 {
					echoTxn = binary.BigEndian.Uint32(v[:4])
				}
				_ = writeCNTFull(ep, cntMsgBound, m.Token, echoTxn)
				continue
			}
			Logp("mtp: server MediaBinding response %s\n", m.summary())
			goto bindDone
		}
	}
bindDone:
	if !got12 {
		// Retry MediaBinding+bound on each answered endpoint (primary first)
		// before accepting a half-open session — incomplete bind often yields
		// KCP ACKs only and RDT/timeline then times out.
		var candidates []mediaEndpoint
		for _, e := range eps {
			if answered[string(e.Session)] {
				candidates = append(candidates, e)
			}
		}
		if len(candidates) == 0 {
			for _, e := range eps {
				if _, ok := acked[string(e.Session)]; ok {
					candidates = append(candidates, e)
				}
			}
		}
		if len(candidates) == 0 {
			candidates = []mediaEndpoint{ep}
		}
		Logp("mtp: bind incomplete; retrying MediaBinding on %d eps\n", len(candidates))
		for _, cand := range candidates {
			ep = cand
			for attempt := 1; attempt <= 2 && !got12; attempt++ {
				Logp("mtp: bind retry %d sess=%x %s:%d\n", attempt, ep.Session, ep.IP, ep.Port)
				_ = writeCNT(ep, cntMsgReply, nil)
				_ = writeCNT(ep, cntMsgPunch, nil)
				_ = writeCNT(ep, cntMsgBound, nil)
				_ = writeCNT(ep, cntMsgPunch2, nil)
				sendSelfMapPunch()
				deadline := time.Now().Add(2500 * time.Millisecond)
				for time.Now().Before(deadline) && !got12 {
					e2, m, err := waitAny(time.Until(deadline), nil, func(m *mediaCNT, _ mediaEndpoint) bool {
						return m.Kind == cntKindBinding || m.Kind == cntKindBound ||
							(m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch)
					})
					if err != nil {
						break
					}
					ep = e2
					if m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch {
						echoTxn := uint32(0)
						if v := m.TLVs[tlvTransactionID]; len(v) >= 4 {
							echoTxn = binary.BigEndian.Uint32(v[:4])
						}
						_ = writeCNTFull(ep, cntMsgBound, m.Token, echoTxn)
						_ = writeCNT(ep, cntMsgPunch2, nil)
						got12 = true
						Logp("mtp: bind retry got punch2 — ready\n")
						break
					}
					Logp("mtp: bind retry got %s — ready\n", m.summary())
					got12 = true
					break
				}
			}
			if got12 {
				break
			}
		}
		if !got12 {
			Logp("mtp: bind still incomplete after retries; proceeding with fallback on %s:%d\n",
				ep.IP, ep.Port)
			_ = writeCNT(ep, cntMsgBound, nil)
			_ = writeCNT(ep, cntMsgPunch2, nil)
		}
	}

	mediaVA := net.JoinHostPort(ep.IP.String(), fmt.Sprintf("%d", ep.Port))
	if err := c.sendDataConnectionReadyVia(conn, ep.Session, mediaVA); err != nil {
		Logp("mtp: DATA_CONNECTION_READY: %v\n", err)
	}
	if err := c.sendCandidateListVia(conn, mappedAddrs); err != nil {
		Logf("mtp: candidate-list: %v\n", err)
	}

	authSign := deriveAuthSignKey(c.authTok)
	remote := &net.UDPAddr{IP: ep.IP, Port: int(ep.Port)}
	sk := c.mediaShareKey()
	if len(ep.ShareKey) == 32 {
		sk = ep.ShareKey
	}
	Logp("mtp: media session %s:%d sess=%x shareKey=%s bindOK=%v\n",
		ep.IP, ep.Port, ep.Session,
		map[bool]string{true: "ep", false: "primary"}[len(ep.ShareKey) == 32],
		got12)
	ms := &mediaSession{
		conn:     conn,
		remote:   remote,
		session:  append([]byte(nil), ep.Session...),
		ep:       ep,
		shareKey: sk,
		authSign: authSign,
		signKey:  deriveShareSignKey(sk),
		kcp:      newMediaKCP(ep.Session, authSign),
		ackPad:   0x0a, // next ACK uses 0x0b000000 (native)
		cntSeq:   4,    // bind used 1..4-ish; keep climbing
		parent:   c,
		frags:    make(map[uint16][]byte),
	}
	if got12 {
		ms.bindOK.Store(true)
	}
	c.mediaSess.Store(ms)
	ms.bound.Store(true) // CNT~ keepalives (0x12→0x13) answered by handleCNT
	c.startMediaKeepalive(conn)
	ms.startMediaBindHeartbeat()
	if err := ms.sendBootstrap(); err != nil {
		return err
	}
	ms.bootOK.Store(true)
	_ = c.sendVideoStartStatusVia(conn)
	// After first frame, ReadPacket uses long/refreshed deadlines (see handle / producer).
	ms.parent.deadline.Store(time.Now().Add(60 * time.Second))
	waitVideo := time.After(30 * time.Second)
	var nudgeCh <-chan time.Time = time.After(8 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	mediaReady := func() bool {
		return ms.gotVideo.Load() || ms.chkAlive.Load()
	}
	for {
		select {
		case <-c.closed:
			return nil
		case <-nudgeCh:
			nudgeCh = nil
			if !mediaReady() {
				Logp("mtp: no CHK/video after 8s; nudging live start\n")
				_ = ms.sendCommand(0x102, `{}`)
				_ = ms.sendCommand(0x109, `{"videoquality":0}`)
				_ = ms.sendCommand(0x104, `{}`)
				_ = c.sendVideoStartStatusVia(conn)
			}
		case <-waitVideo:
			if mediaReady() {
				c.mediaRX = nil
				return nil
			}
			// Keep the bound session; caller WaitMediaReady may still succeed if
			// frames arrive later. Never treat bindOK-only as stream-ready.
			Logp("mtp: no live CHK/video within 30s (bindOK=%v)\n", ms.bindOK.Load())
			c.mediaRX = nil
			return nil
		case <-tick.C:
			if mediaReady() {
				c.mediaRX = nil
				return nil
			}
		case pkt := <-mediaRX:
			if len(pkt) >= 4 && string(pkt[:4]) == "CNT~" {
				ms.handleCNT(pkt)
			} else {
				ms.handle(pkt)
			}
			if mediaReady() {
				c.mediaRX = nil
				return nil
			}
		}
	}
}

func newMediaKCP(session, authSign []byte) *kcpState {
	k := newKCP(session, authSign)
	return k
}

func (ms *mediaSession) sendBootstrap() error {
	// Native order after CNT~ bind: motor/op6, video-start {}, stream-ctrl quality.
	// Audio (0x104) and playback (0x10d/0x10f) are sent later via WriteMediaCommand.
	for _, c := range []struct {
		cmd  uint32
		json string
	}{
		{0x112, `{"operation":6}`},
		{0x102, `{}`},
		{0x109, `{"videoquality":0}`},
	} {
		if err := ms.sendCommand(c.cmd, c.json); err != nil {
			return err
		}
		time.Sleep(400 * time.Millisecond)
	}
	return nil
}

// sendCommand pushes a clear miss cmd on media KCP~/CHK~ (native miss_cmd_send).
func (ms *mediaSession) sendCommand(cmd uint32, jsonStr string) error {
	plain := buildCHKCommandPlain(cmd, []byte(jsonStr))
	pkt := ms.buildMediaPUSH(plain)
	if _, err := ms.write(pkt); err != nil {
		return err
	}
	Logp("mtp: TX CHK~ cmd=0x%x json=%s kcp=%d pad=%d ln=%d\n",
		cmd, jsonStr, len(pkt),
		binary.BigEndian.Uint32(pkt[32:36]),
		binary.BigEndian.Uint32(pkt[28:32]))
	return nil
}

// sendRDT pushes a raw RDT TLV on CHK~ (native mtp_rdt_send / channel 3).
// CHK seq starts at 0 for the session and increments (native later type-6 TX
// uses seq=9,10,…). Resends must not reuse seq=0 or the camera ignores them.
func (ms *mediaSession) sendRDT(payload []byte) error {
	pkt := ms.buildMediaPUSHMode(payload, chkModeRDT)
	if _, err := ms.write(pkt); err != nil {
		return err
	}
	cseq := atomic.LoadUint32(&ms.chkSeqRDT) - 1
	Logp("mtp: TX CHK~ rdt len=%d chkSeq=%d una=%d kcp=%d\n",
		len(payload), cseq, atomic.LoadUint32(&ms.kcp.una), len(pkt))
	return nil
}

func buildCHKCommandPlain(cmd uint32, json []byte) []byte {
	// miss_cmd_send vendor=6: BE(0x1001) || BE(cmd) || json || pad to 4.
	pad := (4 - (len(json) % 4)) % 4
	out := make([]byte, 0, 8+len(json)+pad)
	out = binary.BigEndian.AppendUint32(out, 0x1001)
	out = binary.BigEndian.AppendUint32(out, cmd)
	out = append(out, json...)
	if pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

func (ms *mediaSession) buildMediaPUSH(chkPlain []byte) []byte {
	return ms.buildMediaPUSHMode(chkPlain, chkModeCtrl)
}

func (ms *mediaSession) buildMediaPUSHMode(chkPlain []byte, mode int) []byte {
	var seq uint32
	if mode == chkModeRDT {
		seq = atomic.AddUint32(&ms.chkSeqRDT, 1) - 1
	} else {
		seq = atomic.AddUint32(&ms.chkSeq, 1) - 1
	}
	chk := buildCHK(ms.session, ms.shareKey, seq, 0, chkPlain, 0, mode)
	sn := ms.kcp.nextSN()
	pkt := packKCP(magicKCPt, ms.session, kcpCmdPush, 0, 128, sn, atomic.LoadUint32(&ms.kcp.una), chk)
	// Native media PUSH pad increments (RDT TX uses pad≈0x164 in pcap).
	pad := atomic.AddUint32(&ms.ackPad, 1)
	binary.BigEndian.PutUint32(pkt[32:36], pad)
	return finalizeMediaSigns(pkt, ms.authSign, ms.signKey)
}

func packKCP(magic string, session []byte, cmd, frg byte, wnd uint16, sn, una uint32, payload []byte) []byte {
	out := make([]byte, 12+kcpHdrSize+len(payload))
	copy(out[0:4], magic)
	copy(out[4:12], session)
	out[12] = cmd
	out[13] = frg
	binary.BigEndian.PutUint16(out[14:16], wnd)
	binary.BigEndian.PutUint32(out[16:20], uint32(time.Now().UnixMilli()))
	binary.BigEndian.PutUint32(out[20:24], sn)
	binary.BigEndian.PutUint32(out[24:28], una)
	binary.BigEndian.PutUint32(out[28:32], uint32(len(payload)))
	copy(out[36:], payload)
	return out
}

// buildCHK builds CHK~ with ChaCha20(shareKey) body.
//
//	CHK~ || session8 || seq_BE32 || 0 || (flag<<16|lenish) || ts12 ||
//	  nonce8 || cipher(plain)
//
// mode chkModeRDT uses field 0xd8xx (native RDT); otherwise 0xc0xx control.
func buildCHK(session, shareKey []byte, seq, frag uint32, plain []byte, sizeHint uint16, mode int) []byte {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	cipher := make([]byte, len(plain))
	chacha20XOR(cipher, plain, nonce, shareKey)
	blob := append(append([]byte(nil), nonce...), cipher...)

	var field uint32
	if frag != 0 || sizeHint != 0 {
		field = (frag << 16) | uint32(sizeHint)
	} else if mode == chkModeRDT {
		// Native type-6 TX: field=0xd820 for blob=32 (nonce8+plain24).
		field = chkRDTFlag | uint32(len(blob))
	} else {
		// Control probes (Frida): 0xc01f / 0xc012 / 0xc022 for blob 32/20/36.
		// First matches blob-1; 2nd/3rd match blob-2 (native wire values).
		switch len(blob) {
		case 32:
			field = chkCtrlFlag | 0x01f
		case 20:
			field = chkCtrlFlag | 0x012
		case 36:
			field = chkCtrlFlag | 0x022
		default:
			field = chkCtrlFlag | uint32(len(blob)-1)
		}
	}

	ts := uint32(time.Now().UnixMilli())
	out := make([]byte, 0, chkHdrSize+len(blob))
	out = append(out, magicCHK...)
	if len(session) >= 8 {
		out = append(out, session[:8]...)
	} else {
		out = append(out, make([]byte, 8)...)
	}
	out = binary.BigEndian.AppendUint32(out, seq)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = binary.BigEndian.AppendUint32(out, field)
	out = binary.BigEndian.AppendUint32(out, ts)
	out = append(out, 0x00, 0x00, 0xe0, 0x00) // matches native @28..
	out = append(out, 0, 0, 0, 0)
	out = append(out, blob...)
	return out
}

// finalizeMediaSigns appends ServerSign (auth, window 88) + PacketSign + OB footer.
//
// PacketSign for CHK~ is CityHash128WithSeed(CHK[:52], shareSign seeds), not HMAC.
// Value is mac16 || zeros16 || 00 20 || BE16(52).
//
// Native KCP ln covers CHK + all trailers (totalLen - 36). ln sits inside the
// ServerSign window (88 B), so it must be set to the final value BEFORE HMAC.
func finalizeMediaSigns(pkt, authSign, shareSign []byte) []byte {
	const trailers = 40 + 40 + 16 // ServerSign + PacketSign + OB
	if len(pkt) >= 36 {
		binary.BigEndian.PutUint32(pkt[28:32], uint32(len(pkt)-36+trailers))
	}

	signed := mediaKCPSignLen
	if signed > len(pkt) {
		signed = len(pkt)
	}
	pkt = binary.BigEndian.AppendUint16(pkt, tlvServerSign)
	pkt = binary.BigEndian.AppendUint16(pkt, fieldSignValueLen)
	mac := hmac.New(sha256.New, authSign)
	mac.Write(pkt[:signed])
	pkt = append(pkt, mac.Sum(nil)...)
	pkt = binary.BigEndian.AppendUint16(pkt, signTrailerMagic)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(mediaKCPSignLen))

	chkOff := 36
	psWin := mediaPacketSignN
	if chkOff+psWin > len(pkt) {
		psWin = len(pkt) - chkOff
	}
	pkt = binary.BigEndian.AppendUint16(pkt, tlvPacketSign)
	pkt = binary.BigEndian.AppendUint16(pkt, fieldSignValueLen)
	pkt = append(pkt, cityHash128MAC16(pkt[chkOff:chkOff+psWin], shareSign)...)
	pkt = append(pkt, make([]byte, 16)...)
	pkt = binary.BigEndian.AppendUint16(pkt, signTrailerMagic)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(mediaPacketSignN))

	ts := uint64(time.Now().UnixMilli())
	pkt = append(pkt, 'O', 'B', 0x00, 0x0c)
	pkt = binary.BigEndian.AppendUint32(pkt, 8)
	pkt = binary.BigEndian.AppendUint64(pkt, ts)
	return pkt
}

func (ms *mediaSession) buildACK(sn, una uint32) []byte {
	return ms.buildACKBatch([]uint32{sn}, una)
}

// buildACKBatch matches native media ACKs: N×36 B KCP~ headers, only the last
// has ServerSign (76 B). pad on the first seg is 0xNN000000 (NN increments).
func (ms *mediaSession) buildACKBatch(sns []uint32, una uint32) []byte {
	if len(sns) == 0 {
		return nil
	}
	padN := atomic.AddUint32(&ms.ackPad, 1)
	out := make([]byte, 0, 36*len(sns)+40)
	for i, sn := range sns {
		pkt := packKCP(magicKCPt, ms.session, kcpCmdACK, 0, 0x007f, sn, una, nil)
		if i == 0 {
			binary.BigEndian.PutUint32(pkt[32:36], padN<<24)
		}
		out = append(out, pkt[:36]...)
		if i < len(sns)-1 {
			continue
		}
		out = binary.BigEndian.AppendUint16(out, tlvServerSign)
		out = binary.BigEndian.AppendUint16(out, fieldSignValueLen)
		mac := hmac.New(sha256.New, ms.authSign)
		mac.Write(pkt[:36])
		out = append(out, mac.Sum(nil)...)
		out = binary.BigEndian.AppendUint16(out, signTrailerMagic)
		out = binary.BigEndian.AppendUint16(out, 36)
	}
	return out
}

// ackPUSH sends a media ACK with contiguous UNA.
//
// Previously we set una=sn+1 (skip holes) like a low-latency live path; that
// told the relay lost KCP packets were received, so IDR fragments were never
// retransmitted (logs: drop incomplete 297/307) → grey P-frames until the
// next keyframe. Stall UNA on gaps briefly so the peer can retransmit; only
// skip a hole after mediaHoleSkip and then force keyframe resync.
//
// This trade-off is wrong for RDT: forcing una past an unfilled gap tells the
// camera "everything below here is delivered", so it never retransmits the
// missing PUSH — permanently truncating the type-6 index at that byte offset
// (proven live: repeated fetches stalling at an identical ~80 tagged-frame /
// ~2.5 KB prefix, matching the real client's first reassembled chunk size
// exactly, then going silent). Live video tolerates the loss (next keyframe
// fixes it); an index fetch cannot. While rdtListen is set, never force-skip
// — leave the hole open so the camera's own KCP RTO retransmits the missing
// packet, and let FetchTimelineIndex's own deadline bound the wait instead.
const mediaHoleSkip = 800 * time.Millisecond

func (ms *mediaSession) ackPUSH(sn uint32) {
	ms.ackMu.Lock()
	if ms.recvBuf == nil {
		ms.recvBuf = make(map[uint32]struct{}, 64)
	}
	if !ms.recvInit {
		ms.rcvNext = sn
		ms.recvInit = true
	}
	ms.recvBuf[sn] = struct{}{}
	if sn > ms.rcvMax {
		ms.rcvMax = sn
	}
	rdtFetch := ms.rdtListen.Load()
	now := time.Now()
	for {
		if _, ok := ms.recvBuf[ms.rcvNext]; ok {
			delete(ms.recvBuf, ms.rcvNext)
			ms.rcvNext++
			ms.holeSince = time.Time{}
			continue
		}
		if ms.rcvMax < ms.rcvNext {
			break
		}
		// Gap: something above rcvNext was received.
		if ms.holeSince.IsZero() {
			ms.holeSince = now
			if rdtFetch {
				Logp("mtp: KCP hole sn=%d during RDT fetch, waiting for retransmit (una held)\n", ms.rcvNext)
			}
		}
		if rdtFetch {
			break // never force-skip; wait indefinitely for the camera to resend
		}
		if now.Sub(ms.holeSince) < mediaHoleSkip {
			break
		}
		Logf("mtp: KCP skip lost sn=%d after %s (force keyframe)\n", ms.rcvNext, mediaHoleSkip)
		ms.rcvNext++
		ms.holeSince = now
		ms.needKey.Store(true)
	}
	una := ms.rcvNext
	if len(ms.recvBuf) > 512 {
		for k := range ms.recvBuf {
			if k < una {
				delete(ms.recvBuf, k)
			}
		}
	}
	// Native batches several pending ACKs into one datagram (N×36 B headers +
	// one shared 40 B sign trailer — up to 13 in the largest observed capture,
	// 508 B) instead of one immediate ACK per received PUSH. We ack every
	// packet individually, unconditionally — a much higher ACK-datagram rate
	// than native for the same data volume. Untested but plausible given nothing
	// else has explained the hard stop at ~80 RDT-tagged packets: batch during
	// an RDT fetch (only — live video keeps the existing immediate per-packet
	// ack so keyframe-retransmit latency, already tuned via mediaHoleSkip,
	// doesn't regress) in case some rate-based gate on the ACK-datagram count
	// itself is involved.
	var toSend []byte
	if rdtFetch {
		ms.ackPending = append(ms.ackPending, sn)
		if ms.ackBatchStart.IsZero() {
			ms.ackBatchStart = now
		}
		if len(ms.ackPending) >= 13 || now.Sub(ms.ackBatchStart) >= 50*time.Millisecond {
			toSend = ms.buildACKBatch(ms.ackPending, una)
			ms.ackPending = nil
			ms.ackBatchStart = time.Time{}
		}
	} else {
		toSend = ms.buildACK(sn, una)
	}
	ms.ackMu.Unlock()
	// Outgoing PUSH (incl. RDT) must advertise our recv UNA, not the peer's.
	// Native type-6 TX uses una≈1000+ after live video; una≈4 makes the camera
	// silently ignore RDT (deadline exceeded with only KCP ACKs).
	atomic.StoreUint32(&ms.kcp.una, una)
	atomic.AddUint32(&ms.cntSeq, 1)
	if toSend != nil {
		_, _ = ms.write(toSend)
	}
}

// flushPendingACK sends whatever is in ackPending right now, regardless of
// the 13-item/50ms batching thresholds in ackPUSH. Batching only checks those
// thresholds when a new PUSH arrives — if the camera goes quiet right after
// filling a partial batch, those sn's would otherwise sit unacked until more
// data arrives (or forever, if it doesn't), which is exactly the kind of
// stall an ACK batch is supposed to avoid. FetchTimelineIndex calls this on a
// timer so a partial batch is never stuck waiting on new arrivals.
func (ms *mediaSession) flushPendingACK() {
	ms.ackMu.Lock()
	if len(ms.ackPending) == 0 {
		ms.ackMu.Unlock()
		return
	}
	pkt := ms.buildACKBatch(ms.ackPending, ms.rcvNext)
	ms.ackPending = nil
	ms.ackBatchStart = time.Time{}
	ms.ackMu.Unlock()
	_, _ = ms.write(pkt)
}

// startMediaKeepalive mirrors native post-video:
//   - LAN CNT|/CNT}/CNT\x00/\x01 every 0.5s for ~6.5s only (then stop)
//   - media CNT~ 0x12 every 5s (client-initiated); server answers 0x13,
//     then server 0x12 → we reply 0x13 in handleCNT. Without the 5s 0x12
//     heartbeat the relay stops video after a few seconds.
func (c *Conn) startMediaKeepalive(conn *net.UDPConn) {
	if conn == nil || c.loginCtx == nil {
		return
	}
	go func() {
		lan := time.NewTicker(500 * time.Millisecond)
		defer lan.Stop()
		lanEnd := time.After(7 * time.Second)
		lanOn := true
		for lanOn {
			select {
			case <-c.closed:
				return
			case <-lanEnd:
				lanOn = false
				lan.Stop()
			case <-lan.C:
				c.sendMediaKeepaliveOnce(conn)
			}
		}
		// Drain closed while waiting for mediaSess heartbeat (started separately).
		<-c.closed
	}()
	Logp("mtp: LAN keepalive ~0.5s for 7s; media 0x12 heartbeat via session\n")
}

// startMediaBindHeartbeat sends client CNT~ 0x12 every 5s (native long-stream).
func (ms *mediaSession) startMediaBindHeartbeat() {
	go func() {
		// Native: first client 0x12 ~4.55s after video; then every 5.000s.
		select {
		case <-ms.parent.closed:
			return
		case <-time.After(4500 * time.Millisecond):
		}
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		// Send immediately at +4.5s, then on each tick.
		for {
			if err := ms.writeCNT(cntMsgPunch2); err != nil {
				Logf("mtp: media 0x12 heartbeat: %v\n", err)
			} else {
				Logf("mtp: media 0x12 heartbeat (5s)\n")
			}
			select {
			case <-ms.parent.closed:
				return
			case <-t.C:
			}
		}
	}()
}

func (c *Conn) sendMediaKeepaliveOnce(conn *net.UDPConn) {
	if c.loginCtx == nil || conn == nil {
		return
	}
	chanSess := c.channelSession
	if len(chanSess) != 8 {
		chanSess = c.session
	}
	sk := c.mediaShareKey()
	send := func(magic string, dst *net.UDPAddr, epCount uint32) {
		if dst == nil {
			return
		}
		txn := c.loginCtx.nextTransaction()
		pkt := buildLANPunchCNT(magic, chanSess, c.loginCtx, sk, c.localIP, c.cameraIP, epCount, 1, txn)
		if len(pkt) == 0 {
			return
		}
		if _, err := conn.WriteToUDP(pkt, dst); err != nil {
			return
		}
	}
	if c.cameraIP != nil {
		cam := &net.UDPAddr{IP: c.cameraIP, Port: mediaUDPPort}
		send("CNT\x00", cam, 1)
		send("CNT\x01", cam, 1)
	}
	pub := c.loginCtx.buddyAddr
	if len(pub) < 8 {
		pub = c.loginCtx.relayAddr
	}
	if len(pub) >= 8 {
		if v4 := net.IP(pub[4:8]).To4(); v4 != nil && !isZero(v4) {
			p := mediaUDPPort
			if mp := int(binary.BigEndian.Uint16(pub[2:4])); mp != 0 {
				p = mp
			}
			dst := &net.UDPAddr{IP: v4, Port: p}
			send("CNT|", dst, 2)
			send("CNT}", dst, 2)
		}
	}
}

func (ms *mediaSession) loop() error {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ms.parent.closed:
			return nil
		default:
		}
		_ = ms.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := ms.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ms.gotVideo.Load() {
					continue
				}
				return fmt.Errorf("media read timeout")
			}
			return err
		}
		Logf("mtp: media loop RX len=%d magic=%q head=%x\n",
			n, buf[:min(4, n)], buf[:min(20, n)])
		ms.handle(buf[:n])
	}
}

// sessionMatches reports whether sess (an incoming packet's 8-byte session
// field, pkt[4:12]) belongs to this media session. The camera's own packets
// legitimately carry ms.session with the first byte's high bit flipped
// (native convention — see findEP's identical same/flip check used during
// bind), so a naive equality check would wrongly reject every real incoming
// packet, not just foreign ones.
func (ms *mediaSession) sessionMatches(sess []byte) bool {
	if len(ms.session) < 8 || len(sess) < 8 {
		return false
	}
	if bytes.Equal(ms.session, sess[:8]) {
		return true
	}
	return (ms.session[0]^0x80) == sess[0] && bytes.Equal(ms.session[1:8], sess[1:8])
}

func (ms *mediaSession) handle(pkt []byte) {
	if len(pkt) < 4 {
		return
	}
	magic := string(pkt[0:4])
	switch magic {
	case magicKCPt, "KCP\x7f":
		// Extra media endpoints from the punch/bind dance (see findEP above)
		// keep sending on the same shared :40000 socket after we've settled
		// on one session — each has its own shareKey. Without this filter
		// those foreign-session packets get decrypted with OUR shareKey and
		// their ChaCha20 keystream output is effectively random noise,
		// silently corrupting whatever they get appended to (RDT raw
		// accumulation, video reassembly). This mirrors a fix already made
		// on the transport plane (Conn.worker / handlePacket) for the
		// analogous foreign-CNT-session issue — the media plane never got
		// the equivalent check. Proven live: a target's RDT fetch produced
		// an identical clean prefix across independent attempts (same real
		// segments, unchanged seconds apart) but the point and content of
		// corruption after it varied — consistent with foreign-session
		// packets interleaving unpredictably, not a fixed decode bug.
		if len(pkt) >= 12 && !ms.sessionMatches(pkt[4:12]) {
			n := ms.foreignSessionRX.Add(1)
			if n == 1 || n%100 == 0 {
				Logp("mtp: RX media KCP foreign sess=%x (ours=%x), ignore (count=%d)\n", pkt[4:12], ms.session, n)
			}
			return
		}
		cmd, sn, _, payload, ok := parseKCP(pkt)
		if !ok {
			return
		}
		// Do NOT store the peer's una into kcp.una — that field is our recv
		// watermark for outgoing PUSH/RDT (updated in ackPUSH from rcvNext).
		if cmd == kcpCmdACK {
			return
		}
		if cmd == kcpCmdPush {
			ms.ackPUSH(sn)
			// Keep ReadPacket alive while UDP media is flowing (even incomplete frames).
			if ms.parent != nil {
				ms.parent.deadline.Store(time.Now().Add(60 * time.Second))
			}
			if len(payload) >= 4 && string(payload[0:4]) == magicCHK {
				ms.handleCHK(payload)
			}
		}
	case "CNT~":
		ms.handleCNT(pkt)
	}
}

// handleCNT answers post-bind media CNT~ keepalives.
// Native long-stream: one S 0x12 ↔ C 0x13 pair per ~5s (plus client-initiated
// 0x12). Answering every duplicate/retry 0x12 floods the relay; we then see
// msgid 0x14 and video stops. Debounce 0x13 to ≥4s.
func (ms *mediaSession) handleCNT(pkt []byte) {
	m, err := parseMediaCNT(pkt)
	if err != nil {
		Logf("mtp: media CNT~ parse: %v\n", err)
		return
	}
	_ = m.decrypt(ms.shareKey)
	Logf("mtp: media RX CNT~ %s sess=%x\n", m.summary(), m.Session)

	switch {
	case m.MsgID == cntMsgPunch2 && m.Kind == cntKindPunch:
		// Native: C 0x13 echoes S 0x12 token AND txn (0x0008). Fresh values → retries.
		txn := uint32(0)
		if v := m.TLVs[tlvTransactionID]; len(v) >= 4 {
			txn = binary.BigEndian.Uint32(v[:4])
		}
		_ = ms.writeCNTReply(cntMsgBound, m.Token, txn)
		ms.last13.Store(time.Now().UnixNano())
	case m.MsgID == 0x0014:
		Logf("mtp: media CNT~ msgid=0x14 (native never sends; treat as session warn)\n")
	case m.Kind == cntKindBinding || m.Kind == cntKindBound || m.Kind == cntKindPunchACK:
		// server ack / punch-ack after bind — ignore
	case m.MsgID == cntMsgPunch && m.Kind == cntKindPunch:
		// Post-bind server 0x10: native does not re-MediaBind; ignore.
	default:
		Logf("mtp: media CNT~ unhandled msgid=%#x kind=%s\n", m.MsgID, m.kindName())
	}
	if ms.parent != nil {
		ms.parent.deadline.Store(time.Now().Add(60 * time.Second))
	}
}

func (ms *mediaSession) writeCNT(msgID uint16) error {
	return ms.writeCNTReply(msgID, nil, 0)
}

func (ms *mediaSession) writeCNTEcho(msgID uint16, echoToken []byte) error {
	return ms.writeCNTReply(msgID, echoToken, 0)
}

// writeCNTReply builds post-bind CNT~. echoToken/echoTxn: when answering server
// 0x12, native copies both into C 0x13 (pcap). Zero txn → allocate fresh.
func (ms *mediaSession) writeCNTReply(msgID uint16, echoToken []byte, echoTxn uint32) error {
	c := ms.parent
	if c == nil || c.loginCtx == nil {
		return fmt.Errorf("no loginCtx")
	}
	c.loginCtx.timestamp = uint64(time.Now().UnixMilli())
	txn := echoTxn
	if txn == 0 {
		txn = c.loginCtx.nextTransaction()
	}
	seq := atomic.AddUint32(&ms.cntSeq, 1)
	ep := ms.ep
	if len(ep.Session) < 8 {
		ep.Session = ms.session
		ep.IP = ms.remote.IP
		ep.Port = uint16(ms.remote.Port)
	}
	pkt := buildMediaCNTMsg(
		ep, c.loginCtx, ms.shareKey, []byte(c.authTok),
		c.localIP, c.cameraIP, 3, seq, txn, msgID, echoToken,
	)
	addr := ms.remote
	if addr == nil {
		addr = &net.UDPAddr{IP: ep.IP, Port: int(ep.Port)}
	}
	if _, err := ms.conn.WriteToUDP(pkt, addr); err != nil {
		return err
	}
	echo := "rand"
	if len(echoToken) >= 16 {
		echo = fmt.Sprintf("echo=%x", echoToken[:8])
	}
	Logf("mtp: TX CNT~ msgid=%#x %s sess=%x seq=%d txn=%#x len=%d token=%s (post-bind)\n",
		msgID, addr, ep.Session, seq, txn, len(pkt), echo)
	return nil
}

func (ms *mediaSession) handleCHK(pay []byte) {
	if len(pay) < chkHdrSize+8 {
		return
	}
	seq := binary.BigEndian.Uint32(pay[12:16])
	field := binary.BigEndian.Uint32(pay[20:24])
	frag := uint16(field >> 16)
	rest := uint16(field)

	// Strip ServerSign / PacketSign / FOOTER to get cipher blob.
	cipher := pay[chkHdrSize:]
	if i := indexTLV(cipher, tlvServerSign); i >= 0 {
		cipher = cipher[:i]
	}
	if len(cipher) < 9 {
		return
	}
	plain := make([]byte, len(cipher)-8)
	chacha20XOR(plain, cipher[8:], cipher[:8], ms.shareKey)

	// Control is only rest hi-byte 0xc0 (e.g. 0xc03a / 0xc014). Do NOT use
	// rest&0xc000 — that also matches 0xd0xx/0xd1xx single-frag video (P-frames).
	isCtrl := rest>>8 == 0xc0 ||
		(frag == 0 && len(plain) < 64 && plain[0] == 0 && plain[1] == 0)
	if isCtrl {
		if len(plain) >= 8 && binary.BigEndian.Uint32(plain[0:4]) == 0x1001 {
			cmd := binary.BigEndian.Uint32(plain[4:8])
			data := bytes.TrimRight(plain[8:], "\x00")
			Logp("mtp: RX CHK~ ctrl seq=%d cmd=0x%x len=%d %s\n",
				seq, cmd, len(data), truncateASCII(data, 120))
			ms.chkAlive.Store(true)
			// Surface to ReadCommand (e.g. playback 0x10e filefound).
			if ms.parent != nil && ms.parent.channels != nil {
				buf := make([]byte, 4+len(data))
				binary.LittleEndian.PutUint32(buf[0:4], cmd)
				copy(buf[4:], data)
				ms.parent.channels.cmd.Push(buf)
			}
		}
		return
	}

	// Single-frag RDT: native type-6 uses 0xd8xx / 0x58xx. 0x50xx appears in
	// pcaps too but is often non-timeline during live — only accept if content
	// looks like RDT/TimeItems (otherwise it floods the RDT queue with junk).
	hi := rest >> 8
	switch hi {
	case 0xd8, 0x58:
		ms.rdtTaggedRX.Add(1)
		// RDT CHK seq shares the number space with video; clear stale video
		// reassembly so we don't spam "drop incomplete".
		if ms.rdtListen.Load() && seq == ms.frameSeq {
			ms.frags = make(map[uint16][]byte)
			ms.frameNeed = 0
		}
		// Do not log per-frame during listen — thousands of 16 B chunks; logging
		// stalls the UDP reader and the RDT queue overflows.
		ms.pushRDTOrMedia(plain, true, seq)
		return
	case 0x50:
		if looksLikeRDTHeader(plain) || looksLikeTimelineBody(plain) ||
			(ms.rdtListen.Load() && extractTimelineBytes(plain) != nil) {
			ms.rdtTaggedRX.Add(1)
			ms.pushRDTOrMedia(plain, true, seq)
			return
		}
	}

	// Multi-fragment RDT continuation: proven live (2026-08-02, mtp-dissect.py
	// byte-level verification against a fresh capture) that native sends the
	// bulk of the type-6 index via frag>0 packets tagged like real video
	// (rest hi-byte 0x9c/0x1c, matching classify_chk's video-keyfrag pattern
	// in the same third-party tool — an independent confirmation this isn't
	// just our own bug). Each such fragment decrypts to a COMPLETE, self-
	// contained run of TimeItem records on its own — the frag numbering is
	// irrelevant to RDT content, just reused video-fragment framing — so
	// there is nothing to reassemble. Requiring the full frag 0..need set
	// before ever inspecting content (the video reassembly path below) meant
	// a single lost sibling fragment discarded an entire ~127-record chunk;
	// this is why fetches plateaued at a few hundred records out of ~10,000+
	// regardless of how much more raw traffic arrived. Only 0xd8/0x58/0x50
	// were ever recognized as RDT-tagged; check content directly here before
	// falling into frag reassembly, which real video still needs.
	if ms.rdtListen.Load() && frag > 0 && looksLikeTimelineBody(plain) {
		ms.rdtTaggedRX.Add(1)
		ms.pushRDTOrMedia(plain, true, seq)
		return
	}

	// Video / RDT fragment: reassemble frag N..0 into one miss packet.
	if seq != ms.frameSeq {
		if len(ms.frags) > 0 {
			if ms.rdtListen.Load() {
				// Multi-fragment reassembly requires every fragment 0..need
				// before pushRDTOrMedia ever sees the frame — a single
				// missing fragment silently discards the whole thing. If
				// genuine RDT type-6 continuation data is ever sent via
				// multi-fragment framing (not just the single-fragment
				// 0xd8/0x58 case above), this is a candidate explanation for
				// losing large chunks of it without any visible signal
				// (Logf below is invisible under mtp_verbose:false).
				Logp("mtp: drop incomplete during RDT fetch seq=%d have=%d/%d\n",
					ms.frameSeq, len(ms.frags), ms.frameNeed+1)
			}
			Logf("mtp: drop incomplete seq=%d have=%d/%d\n",
				ms.frameSeq, len(ms.frags), ms.frameNeed+1)
			// Lost part of a multi-frag AU (often an IDR) — suppress P-frames
			// until the next IRAP so grey concealment is not recorded.
			if ms.frameNeed > 0 {
				ms.needKey.Store(true)
			}
		}
		ms.frags = make(map[uint16][]byte)
		ms.frameSeq = seq
		ms.frameNeed = frag
	}
	ms.frags[frag] = plain
	if frag > ms.frameNeed {
		ms.frameNeed = frag
	}

	// Wait until we have 0..frameNeed (first high-frag packet sets need).
	for i := uint16(0); i <= ms.frameNeed; i++ {
		if _, ok := ms.frags[i]; !ok {
			return
		}
	}
	var frame []byte
	for i := ms.frameNeed; ; i-- {
		frame = append(frame, ms.frags[i]...)
		if i == 0 {
			break
		}
	}
	// A miss-cmd frame (BE32 0x1001 prefix, e.g. 0x10e playback response) must
	// never be silently dropped by the frag0-only guard below. In practice a
	// real 0x10e is classified as ctrl earlier (rest>>8==0xc0, handled at the
	// top of handleCHK) and never reaches here — but if that classification
	// ever misses one (unusual rest tag, corrupted field), this was the exact
	// shape of frame the guard below would eat with zero diagnostic: single
	// fragment, not RDT-shaped, not a video codec. Check for it first so that
	// can never happen again.
	if isMissCmdFrame(frame) {
		ms.frags = make(map[uint16][]byte)
		ms.pushRDTOrMedia(frame, false, seq)
		return
	}
	// frag0-only without miss/RDT/video: during RDT listen, still deliver
	// (native TimeItem chunks are often single-frag non-video).
	if !looksLikeRDTHeader(frame) && !isMissVideoFrame(frame) && ms.frameNeed == 0 {
		if !ms.rdtListen.Load() && !looksLikeTimelineBody(frame) {
			return
		}
	}
	ms.frags = make(map[uint16][]byte)
	// Not CHK-tagged as RDT (this is the generic frag-reassembly path, shared
	// with video) — isMissVideoFrame must still gate here so real video isn't
	// misrouted into the RDT queue.
	ms.pushRDTOrMedia(frame, false, seq)
}

func isMissCmdFrame(frame []byte) bool {
	return len(frame) >= 8 && binary.BigEndian.Uint32(frame[0:4]) == 0x1001
}

// encodeRDTQueueItem/decodeRDTQueueItem prefix a 4-byte BE CHK-level `seq`
// onto payloads pushed to channels.rdt. UDP does not guarantee delivery
// order, and handleCHK processes packets as they physically arrive — without
// this, out-of-order arrival (not even true packet loss, just normal network
// reordering) silently corrupts every consumer that concatenates RDT bytes
// in receive order (FetchTimelineIndex's raw accumulation, its implicit
// per-chunk continuation, and its explicit-header body accumulation all do
// this). Proven live: a KCP receive watermark (`una`) frozen at a gap while
// hundreds of RDT-tagged frames kept arriving and accumulating — those later
// frames were being appended past an unresolved hole, not after it in true
// sequence. FetchTimelineIndex sorts each drained burst by this seq before
// processing instead of trusting arrival order.
func encodeRDTQueueItem(seq uint32, payload []byte) []byte {
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], seq)
	copy(buf[4:], payload)
	return buf
}

func decodeRDTQueueItem(item []byte) (seq uint32, payload []byte) {
	if len(item) < 4 {
		return 0, item
	}
	return binary.BigEndian.Uint32(item[0:4]), item[4:]
}

// pushRDTOrMedia routes a frame to the RDT queue, the cmd queue, or video
// reassembly. knownRDT must be true only when the CALLER already classified
// this frame as RDT via the CHK field (rest hi-byte 0xd8/0x58, or an accepted
// 0x50) — see handleCHK's `case 0xd8, 0x58` / `case 0x50`. For those frames
// the isMissVideoFrame check below must be skipped: it was silently
// misrouting genuine RDT records to video reassembly (and from there,
// discarding them) whenever a record's second 4-byte field — a duration in
// seconds — coincidentally equaled a codec ID (4, 5, or 40s durations are
// entirely plausible in the real index, see x/rdt-type6.bin's 21-316s
// spread). Proven live: a fetch where the camera sent 80 RDT-tagged CHK
// frames but the reassembler still reported "no header/body" — the frames
// were being classified correctly at the CHK layer and then lost here.
//
// seq is the CHK-level frame sequence number (handleCHK's `seq`, from
// pay[12:16]) — see encodeRDTQueueItem's doc comment for why it's threaded
// through to the RDT queue.
func (ms *mediaSession) pushRDTOrMedia(frame []byte, knownRDT bool, seq uint32) {
	if ms.parent == nil || ms.parent.channels == nil {
		return
	}
	// Never stuff miss cmds into the RDT body queue — a 0x10e (len%8!=0) during
	// type-6 reassembly misaligns (start,dur) pairs and invents garbage TimeItems.
	if isMissCmdFrame(frame) {
		cmd := binary.BigEndian.Uint32(frame[4:8])
		data := bytes.TrimRight(frame[8:], "\x00")
		Logp("mtp: RX CHK~ ctrl (via media) cmd=0x%x len=%d %s\n",
			cmd, len(data), truncateASCII(data, 120))
		ms.chkAlive.Store(true)
		buf := make([]byte, 4+len(data))
		binary.LittleEndian.PutUint32(buf[0:4], cmd)
		copy(buf[4:], data)
		ms.parent.channels.cmd.Push(buf)
		return
	}
	// RDT demux:
	//  - header frames: only when parseRDTHeader proves a valid TLV
	//  - body chunks: only while SetRDTListen, never video/cmd
	// Contamination of 0x10e into the body queue historically invented
	// garbage TimeItems (huge dur); miss cmds are routed above.
	if looksLikeRDTHeader(frame) {
		Logf("mtp: RX RDT frame bytes=%d head=%x\n", len(frame), frame[:min(16, len(frame))])
		ms.parent.channels.rdt.Push(encodeRDTQueueItem(seq, frame))
		return
	}
	// Sanity cap: a genuine single RDT wire deliverable (CHK-tagged fragment,
	// or a reassembled implicit chunk) is at most a few KB — native captures
	// show ~2 KB per callback (x/frida-mtp-capture.log "type6-start"
	// bodyGot=2032). Proven live: a multi-fragment-reassembled blob (almost
	// certainly a real video frame that isMissVideoFrame failed to recognize
	// — its codec check requires an exact match on bytes[4:8]) reached this
	// path at 245 KB and polluted the RDT accumulation, overshooting
	// rdtRawHardCap by 8x in one append. Reject anything implausibly large
	// rather than trust rdtListen/isMissVideoFrame alone.
	if ms.rdtListen.Load() && len(frame) >= 8 && len(frame) <= rdtMaxSingleFrameSize && (knownRDT || !isMissVideoFrame(frame)) {
		ms.parent.channels.rdt.Push(encodeRDTQueueItem(seq, frame))
		return
	}
	if len(frame) < 32 {
		return
	}
	if !isMissVideoFrame(frame) && len(frame) < 256 {
		return
	}
	if ms.needKey.Load() {
		if !missFrameHasIRAP(frame) {
			return
		}
		ms.needKey.Store(false)
		Logf("mtp: keyframe resync seq=%d bytes=%d\n", ms.frameSeq, len(frame))
	}
	if isMissVideoFrame(frame) {
		codec := binary.LittleEndian.Uint32(frame[4:8])
		Logf("mtp: RX media frame seq=%d frags=%d bytes=%d codec=%d\n",
			ms.frameSeq, ms.frameNeed+1, len(frame), codec)
	} else {
		Logf("mtp: RX media frame (nonstd hdr) seq=%d frags=%d bytes=%d\n",
			ms.frameSeq, ms.frameNeed+1, len(frame))
	}
	ms.gotVideo.Store(true)
	ms.chkAlive.Store(true)
	ms.parent.channels.media.Push(frame)
}

// missFrameHasIRAP reports HEVC IRAP (16–21) or AVC IDR in the miss payload.
func missFrameHasIRAP(frame []byte) bool {
	if len(frame) < 36 {
		return false
	}
	p := frame[32:]
	for i := 0; i+5 < len(p); i++ {
		var sc int
		if p[i] == 0 && p[i+1] == 0 && p[i+2] == 0 && p[i+3] == 1 {
			sc = 4
		} else if p[i] == 0 && p[i+1] == 0 && p[i+2] == 1 {
			sc = 3
		} else {
			continue
		}
		nal0 := p[i+sc]
		hevc := (nal0 >> 1) & 0x3f
		if hevc >= 16 && hevc <= 21 {
			return true
		}
		if nal0&0x1f == 5 {
			return true
		}
		i += sc
	}
	for i := 0; i+4 <= len(p); {
		n := int(binary.BigEndian.Uint32(p[i:]))
		i += 4
		if n <= 0 || i+n > len(p) {
			break
		}
		nal0 := p[i]
		hevc := (nal0 >> 1) & 0x3f
		if hevc >= 16 && hevc <= 21 {
			return true
		}
		if nal0&0x1f == 5 {
			return true
		}
		i += n
	}
	return false
}

func indexTLV(buf []byte, typ uint16) int {
	want := []byte{byte(typ >> 8), byte(typ)}
	for i := 0; i+4 <= len(buf); i++ {
		if buf[i] == want[0] && buf[i+1] == want[1] && buf[i+2] == 0x00 && buf[i+3] == 0x24 {
			return i
		}
	}
	return -1
}

func truncateASCII(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
